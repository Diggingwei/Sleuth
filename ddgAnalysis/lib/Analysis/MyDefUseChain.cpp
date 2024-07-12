//===-- DefUseChain.cpp - Static def-use analysis ---------------*- C++ -*-===//
///
/// \file
/// Perform a static def-use chain analysis, we aim to get the target def-use chain, use backward analysis and normal analysis.
///
//===----------------------------------------------------------------------===//

#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include "Graphs/VFG.h"
#include "MemoryModel/PointerAnalysis.h"
#include "SVF-FE/LLVMModule.h"
#include "SVF-FE/SVFIRBuilder.h"
#include "Util/Options.h"
#include "WPA/Andersen.h"
#include "WPA/AndersenSFR.h"
#include "WPA/Steensgaard.h"
#include "WPA/TypeAnalysis.h"

#include "fuzzalloc/Analysis/DefUseChain.h"
#include "fuzzalloc/Analysis/MemFuncIdentify.h"
#include "fuzzalloc/Analysis/VariableRecovery.h"
#include "fuzzalloc/Metadata.h"
#include "fuzzalloc/Streams.h"
#include "fuzzalloc/fuzzalloc.h"

#define DEBUG_TYPE "fuzzalloc-def-use-chain"

using namespace llvm;
using namespace SVF;
using namespace sys;

namespace{
    //
    // Helper functions
    //

static std::string getNameOrAsOperand(const Value *V){
    if (!V->getName().empty()){
        return std::string{V->getName()};
    }

    std::string Name;
    raw_string_ostream OS{Name};
    V->printAsOperand(OS, false);
    return OS.str();
}

static bool isTaggedVar(const Value *V){
    if(!V){
        return false;
    }
    if (const auto *I = dyn_cast<Instruction>(V)){
        return I->getMetadata(kFuzzallocTagVarMD) != nullptr;
    } else if(const auto *GO = dyn_cast<GlobalObject>(V)){
        return GO->getMetadata(kFuzzallocTagVarMD) != nullptr;
    }
    return false;
}

static bool isInstrumentedDeref(const Value *V){
    if (!V) {
        return false;
    }
    if (const auto *I = dyn_cast<Instruction>(V)) {
        return I->getMetadata(kFuzzallocInstrumentedUseSiteMD) != nullptr;
    }
    return false;
}

}   // anonymous namespace

//
// Definition site
//

DefSite::DefSite(const VFGNode *N, const DIVariable *DIVar, const DebugLoc *DL, const int L)
    :Node(N), Val(Node->getValue()), DIVar(DIVar), Loc(DL), Level(L){}

//
// Use Site
//

UseSite::UseSite(const VFGNode *N, const int L)
    :Node(N), Level(L), Val(N->getValue()), Loc(cast<Instruction>(Val)->getDebugLoc()){}

/* Collect value */
void collectValue(std::vector<const SVF::Value*> &SVFGCollect, const SVF::Instruction *StmtInst){

    if (auto ST = dyn_cast<StoreInst>(StmtInst)){
        const Value* Variable = ST->getPointerOperand();        //where we are writing to
        SVFGCollect.push_back(Variable);
    }else if (auto LOI = dyn_cast<LoadInst>(StmtInst)){
        const Value* Variable = LOI->getPointerOperand();       //where we are reading from
        SVFGCollect.push_back(Variable);
    }else if (auto BCI = dyn_cast<BitCastInst>(StmtInst)){
        const Value* Variable = dyn_cast<Value>(BCI);
        SVFGCollect.push_back(Variable);
    }else if (auto CI = dyn_cast<CallInst>(StmtInst)){
        Function* FC = CI->getCalledFunction();
        int argStart = 0;
        if (FC == nullptr){
            return;
        }
        if (FC->isIntrinsic()){
            switch(FC->getIntrinsicID()){
                case Intrinsic::memcpy: {
                    const Value* Variable = CI->getArgOperand(0);
                    SVFGCollect.push_back(Variable);
                    break;
                }
                case Intrinsic::memset: {
                    break;
                }
                case Intrinsic::memmove: {
                    const Value* Variable = CI->getArgOperand(0);
                    SVFGCollect.push_back(Variable);
                    break;
                }
            }
        }
    }

}


/*Cillect the vuln information*/
void initBugInfo(std::vector<BugInformation*> &BugCollect, std::string &filename){
    /*read the file that saves the PoC location*/
    std::ifstream readFile_1;
    readFile_1.open(filename, std::ios::in);
    if(!readFile_1.is_open()){
        LLVM_DEBUG(dbgs() << "initial file is not exit\n");
    }
    std::string initFile;
    if(getline(readFile_1, initFile)){
        LLVM_DEBUG(dbgs() << "read file succeed\n");
    }
    else{
        LLVM_DEBUG(dbgs() << "fail to read file");
    }

    /*read the PoC information*/
    std::ifstream readFile_2;
    readFile_2.open(initFile, std::ios::in);
    if(!readFile_2.is_open()){
        LLVM_DEBUG(dbgs() << "file is not exit\n");
    }

    std::string infobuf;

    /*information phase*/
    int count_null = 1;
    while (getline(readFile_2, infobuf)){
        if (infobuf.size() == 0){
            count_null++;
        }
    }

    readFile_2.clear();
    readFile_2.seekg(0, ios::beg);


    /*information collect*/
    for (int i = 0; i < count_null; i++){
        std::string _BugType;
        std::string _BugOpt;
        std::string _BugBit;
        std::map<std::string, std::tuple<std::string, std::string, std::string, std::string>> _BugInfo;
        while (getline(readFile_2, infobuf)){
            if (infobuf.size() == 0){
                break;
            }
            else{
                StringRef readbuf = StringRef(infobuf);
                if (infobuf.find("==type==") != std::string::npos){
                    _BugType = readbuf.split(" ").second;
                }
                else if (infobuf.find("==opt==") != std::string::npos){
                    _BugOpt = readbuf.split(" ").second;
                }
                else if (infobuf.find("=bit=") != std::string::npos){
                    _BugBit = readbuf.split(" ").second;
                }
                else{
                    auto SiteI = readbuf.split(" ").second;
                    auto SiteF = SiteI.split(" ").first.str();  //function
                    auto SiteC = SiteI.split(" ").second;       //file and location
                    auto SiteP = SiteC.split(":").first.str();  //file
                    auto SiteL = SiteC.split(":").second; //row and col
                    auto SiteR = SiteL.split(":").first.str();  //row
                    auto SiteM = SiteL.split(":").second.str(); //col
                    std::tuple<std::string, std::string, std::string, std::string> SiteEL = {SiteF, SiteP, SiteR, SiteM};
                    if (infobuf.find("==alloc==") != std::string::npos){
                        _BugInfo["alloc"] = SiteEL;
                    }
                    else if (infobuf.find("==site==") != std::string::npos){
                        _BugInfo["site"] = SiteEL;
                    }
                    else if (infobuf.find("==free==") != std::string::npos){
                        _BugInfo["free"] = SiteEL;
                    }
                }
            }
        }
        BugInformation *InfoStore = new BugInformation(_BugType, _BugOpt, _BugBit, _BugInfo);
        BugCollect.push_back(InfoStore);

    }
    readFile_1.close();
    readFile_2.close();
}

//
// Def-use chains
//

char DefUseChain::ID = 0;

DefUseChain::~DefUseChain(){
    delete WPA;
    SVFIR::releaseSVFIR();
    LLVMModuleSet::releaseLLVMModuleSet();
}

std::string init_filename = "/src/vulnInfo/PoC_in.txt";
std::vector<BugInformation*> _BugCollect;           //collect all bug information
std::vector<std::tuple<std::string, std::string>> UseCollect;                //collect all use site in PoC

void DefUseChain::getAnalysisUsage(AnalysisUsage &AU) const{
    AU.addRequired<VariableRecovery>();
    AU.addRequired<MemFuncIdentify>();
    AU.setPreservesAll();
}

bool DefUseChain::runOnModule(Module &M){
    const auto &SrcVars = getAnalysis<VariableRecovery>().getVariables();
    const auto &MemFuncs = getAnalysis<MemFuncIdentify>().getFuncs();

    const char* path_value = std::getenv("SLEUTH_PATH");
    if (path_value != nullptr) {
        std::cout << "SLEUTH_PATH: " << path_value << std::endl;
    } else {
        std::cout << "Not set SLEUTH_PATH" << std::endl;
    }

    std::string poc_filename = path_value + init_filename;

    // Initialize external API
    auto *Externals = ExtAPI::getExtAPI();
    for (const auto *MemFn : MemFuncs){
        const auto &Name = MemFn->getName();
        if (Externals->get_type(Name.str()) != ExtAPI::extType::EFT_NULL){
            continue;
        }

        //find malloc function
        if (StringRef(Name.lower()).contains("malloc") ||
            StringRef(Name.lower()).contains("calloc")){
                Externals->add_entry(Name.str().c_str(), ExtAPI::extType::EFT_ALLOC, true);
            } else if (StringRef(Name.lower()).contains("realloc")){
                Externals->add_entry(Name.str().c_str(), ExtAPI::extType::EFT_REALLOC, true);
            } else if (StringRef(Name.lower()).contains("strdup")){
                Externals->add_entry(Name.str().c_str(), ExtAPI::extType::EFT_NOSTRUCT_ALLOC, true
                );
            }
    }

    //Initial SVF analysis
    auto *SVFMod = LLVMModuleSet::getLLVMModuleSet()->buildSVFModule(M);
    SVFMod->buildSymbolTableInfo();

    //Build SVF IR
    auto *IR = [&SVFMod]() {
        SVFIRBuilder Builder;
        return Builder.build(SVFMod);
    }();

    // Build and run pointer analysis
    status_stream() << "Doing pointer analysis (";
    WPA = [&]() -> BVDataPTAImpl * {
        if (Options::PASelected.isSet(PointerAnalysis::Andersen_WPA)){
            outs() << "Standard inclusion-based";
            return new Andersen(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::AndersenSCD_WPA)){
            outs() << "Selective cycle detection inclusion-based";
            return new AndersenSCD(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::AndersenSFR_WPA)){
            outs() << "Stride-based field representation include-based";
            return new AndersenSFR(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::AndersenWaveDiff_WPA)){
            outs() << "Diff wave propagation inclusion-based";
            return new AndersenWaveDiff(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::Steensgaard_WPA)){
            outs() << "Steensgaard";
            return new Steensgaard(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::FSSPARSE_WPA)){
            outs() << "Sparse flow-sensitive";
            return new FlowSensitive(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::VFS_WPA)){
            outs() << "Versioned sparse flow-sensitive";
            return new VersionedFlowSensitive(IR);
        } else if (Options::PASelected.isSet(PointerAnalysis::TypeCPP_WPA)){
            outs() << "Type-based fast";
            return new TypeAnalysis(IR);
        } else {
            llvm_unreachable("Unsupported pointer analysis");
        }
    }();
    outs() << ")...\n";

    // Build SVFG
    WPA->analyze();
    auto *VFG = [&]() {
        SVFGBuilder Builder(/*WithIndCall=*/true);
        return Builder.buildFullSVFG(WPA);
    }();

    // Get Absolute Path
    StringRef FilePath = M.getSourceFileName();
    char* AbsolutePath = realpath(FilePath.str().c_str(), NULL);
    if (AbsolutePath != NULL){
        status_stream() << "Get absolute path success!\n";
    } else{
        error_stream() << "Fail to get absolute path.\n";
        ::exit(1);
    }

    //Get the Use Site Of Vulnearable
    status_stream() << "Collecting Target Use Site...\n";
    if (_BugCollect.empty()){
        initBugInfo(_BugCollect, poc_filename);
        std::vector<BugInformation*>::iterator it_bug;
        for (it_bug = _BugCollect.begin(); it_bug != _BugCollect.end(); it_bug++){
            std::map<std::string, std::tuple<std::string, std::string, std::string, std::string>>::iterator it_info;
            std::string bug_opt = (*it_bug)->BugOpt;
            for (it_info = (*it_bug)->BugInfo.begin(); it_info != (*it_bug)->BugInfo.end(); it_info++){
                if (it_info->first == "site"){
                    std::string file_name = std::get<1>(it_info->second);
                    std::string row_loc = std::get<2>(it_info->second);
                    std::string col_loc = std::get<3>(it_info->second);
                    if (file_name == AbsolutePath){
                        outs() << file_name << " " << row_loc << " " << col_loc << "\n";
                        UseCollect.push_back({row_loc, col_loc});
                    }
                }
            }
        }
    }
    if (UseCollect.empty()){
        error_stream() << "No Vulnearable Site!\n";
        ::exit(1);
    }

    //
    // Get The SVFG Nodes of Vuln Site
    //
    std::vector<const SVF::Value*> SVFGCollect;
    std::vector<StmtSVFGNode *> NodeCollect;
    status_stream() << "Collecting SVFG Nodes...\n";

    int up_flag = 0;

    for (const auto &[ID, SVFGNode] : *VFG){
        
        if (isa<StmtSVFGNode>(SVFGNode)){
            StmtSVFGNode *stmtNode = cast<StmtSVFGNode>(SVFGNode);
            NodeCollect.push_back(stmtNode);
            auto StmtInst = stmtNode->getInst();
            if (StmtInst){
                DILocation *Loc_line = StmtInst->getDebugLoc();
                if (Loc_line){
                    std::string Row_line = to_string(Loc_line->getLine());
                    std::string Col_line = to_string(Loc_line->getColumn());
                    for (std::tuple Use : UseCollect){
                        if (Row_line == std::get<0>(Use)){
                            outs() << Row_line << " " << Col_line << "\n";
                        }
                        if (Row_line == std::get<0>(Use) && Col_line == std::get<1>(Use)){
                            up_flag = 1;
                            // if write instruction (we now only fcous on write and read)
                            outs()<< *StmtInst << "\n";
                            collectValue(SVFGCollect, StmtInst);
                        }

                    }
                }
            }
        }
    }
    
    if (up_flag == 0){

        for (StmtSVFGNode *N_ode : NodeCollect){
            auto StmtInst = N_ode->getInst();
            if (StmtInst){
                DILocation *Loc_line = StmtInst->getDebugLoc();
                if (Loc_line){
                    std::string Row_line = to_string(Loc_line->getLine());
                    for (std::tuple Use : UseCollect){
                        if (Row_line == std::get<0>(Use)){
                            outs() << *StmtInst << "\n";
                            collectValue(SVFGCollect, StmtInst);
                        }
                    }
                }
            }
        }

    }
    
    if (SVFGCollect.empty()){
        error_stream() << "No SVFG Node!\n";
        ::exit(1);
    }

    //
    //Get Def Site
    //
    DefSet Defs;
    FIFOWorkList<const VFGNode *> WorkList;
    Set<const VFGNode *> Visited;
    std::map<const VFGNode*, int32_t> LevelList;    // Add level identify
    Set<const VFGNode *> Initial_Def;           // Collect defs from forward analysis

    status_stream() << "Collecting definitions...\n";

    for (const auto &[ID, PAGNode] : *IR){
        if (!(isa<ValVar>(PAGNode) && PAGNode->hasValue())) {
            continue;
        }

        auto *Val = PAGNode->getValue();

        for (const auto Use_Value : SVFGCollect){

            if (Val == Use_Value){
                WorkList.clear();
                Visited.clear();
                
                //Get VFGNode from value
                auto pNode = IR->getGNode(IR->getValueNode(Val));
                const VFGNode *vNode = VFG->getDefSVFGNode(pNode);
                WorkList.push(vNode);
                LevelList[vNode] = 0;
                //backward analysis
                while(!WorkList.empty()){
                    
                    const auto *Node = WorkList.pop();
                    int16_t CurrentLevel = LevelList[Node];

                    for (const auto *Edge : Node->getInEdges()){
                        const auto *Succ = Edge->getSrcNode();
                        if (Succ && Visited.insert(Succ).second){
                            Initial_Def.insert(Succ);
                            WorkList.push(Succ);
                            // If currect succ in LevelList and level is higher, use now level cover the inital level
                            if (LevelList.find(Succ) != LevelList.end()){
                                if (LevelList[Succ] > CurrentLevel + 1){
                                    LevelList[Succ] = CurrentLevel + 1;
                                }
                            }else{
                                LevelList[Succ] = CurrentLevel + 1;
                            }
                        }

                    }
                }
                
                //obtain vaild def
                for (const auto *Def : Visited){
                    const auto Def_val = Def->getValue();
                    //if (Def_val){
                        //outs() << *Def_val << "\n";
                    //}
                    if (Def_val && isTaggedVar(Def_val)){
                        //status_stream() << *Def_val << "\n";
                        const auto &SrcVar = SrcVars.lookup(const_cast<Value *>(Def_val));
                        Defs.emplace(Def, SrcVar.getDbgVar(), SrcVar.getLoc(), LevelList[Def]); 
                    }
                }
            }
        }
    }

    if (Defs.empty()){
        error_stream() << "Failed to collect any def site\n";
    }


    //
    //Collect def-use chains
    //
    UseSet Uses;
    size_t NumDefUseChains = 0;
    std::map<const VFGNode *, std::set<const VFGNode *>> Def_Use;

    status_stream() << "Collecting def-use chains...\n";
    for (const auto &Def : Defs){
        WorkList.clear();
        Visited.clear();

        //forward analysis, obition use site
        WorkList.push(Def.Node);
        while (!WorkList.empty()){

            const auto *Node = WorkList.pop();
            int16_t CurrentLevel = LevelList[Node];
            
            //If the initial def
            /*
            if (Initial_Def.find(Node) != Initial_Def.end()){
                CurrentLevel = CurrentLevel - 2;            
            }*/

            for (const auto *Edge : Node->getOutEdges()){
                const auto *Succ = Edge->getDstNode();
                if (Visited.insert(Succ).second){
                    WorkList.push(Succ);
                    if (LevelList.find(Succ) != LevelList.end()){
                        if (LevelList[Succ] > CurrentLevel + 1){
                            LevelList[Succ] = CurrentLevel + 1;
                        }
                    }
                    else{
                        LevelList[Succ] = CurrentLevel + 1;
                    }
                }
            }
        }
        for (const auto *Use : Visited){
            const auto *UseV = Use->getValue();
            if (!isInstrumentedDeref(UseV)){
                continue;
            }
            //Save uses
            Uses.emplace(Use, LevelList[Use]);
            
            if (DefUses[Def].emplace(Use, LevelList[Use]).second){
                NumDefUseChains++;
            }
            
        }
    }

    success_stream() << "Collected " << Uses.size() << " unique uses\n";
    success_stream() << "Collected " << NumDefUseChains << " def-use chains\n";

    return false;
}

//
// JSON helpers
//
json::Value toJSON(const DefSite &Def){
    const auto &VarName = [&]() -> std::string{
        if (const auto *DIVar = Def.DIVar){
            return DIVar->getName().str();
        }
        return getNameOrAsOperand(Def.Val);
    }();

    const auto &File = [&]() -> Optional<StringRef>{
        if (const auto *DIVar = Def.DIVar){
            return DIVar->getFilename();
        }
        return None;
    }();

    const auto &Func = [&]() -> Optional<StringRef> {
        if (const auto *Local = dyn_cast_or_null<DILocalVariable>(Def.DIVar)) {
            return getDISubprogram(Local->getScope())->getName();
        } else if (const auto *Inst = dyn_cast<Instruction>(Def.Val)) {
            return Inst->getFunction()->getName();
        }
        return None;
    }();

    const auto &Line = [&]() -> Optional<unsigned int> {
        if (const auto *DIVar = Def.DIVar) {
            return DIVar->getLine();
        }
        return None;
    }();

    const auto &Col = [&]() -> Optional<unsigned int> {
        if (const auto *Loc = Def.Loc) {
            return Loc->get()->getColumn();
        }
        return None;
    }();

    const auto &Level_number = [&]() -> Optional<unsigned int> {
        if (const auto Level = Def.Level){
            return Level;
        }
        return None;
    }();

    return {VarName, {File, Func, Line, Col, Level_number}};
}

json::Value toJSON(const UseSite &Use) {
    const auto &File = [&]() -> Optional<StringRef> {
        if (const auto &Loc = Use.Loc) {
            auto *SP = getDISubprogram(Loc.getScope());
            return SP->getFile()->getFilename();
        }
        return None;
    }();

    const auto &Func = [&]() -> Optional<StringRef> {
        if (const auto &Loc = Use.Loc) {
            return getDISubprogram(Loc->getScope())->getName();
        } else if (const auto *Inst = dyn_cast<Instruction>(Use.Val)) {
            return Inst->getFunction()->getName();
        }
        return None;
    }();

    const auto &Line = [&]() -> Optional<unsigned int> {
        if (const auto &Loc = Use.Loc) {
            return Loc->getLine();
        }
        return None;
    }();

    const auto &Col = [&]() -> Optional<unsigned int> {
        if (const auto &Loc = Use.Loc) {
            return Loc->getColumn();
        }
        return None;
    }();

    const auto &Level_number = [&]() -> Optional<unsigned int> {
        if (const auto Level = Use.Level){
            return Level;
        }
        return None;
    }();

    return {File, Func, Line, Col, Level_number};
}

json::Value toJSON(const DefUseChain::UseSet &Uses) {
    std::vector<json::Value> J;
    J.reserve(Uses.size());

    for (const auto &U : Uses) {
        J.push_back(U);
    }

    return J;
}

static RegisterPass<DefUseChain> X(DEBUG_TYPE, "Def-use chain analysis", true,
                                   true);

static void registerDefUseChainPass(const PassManagerBuilder &,
                                    legacy::PassManagerBase &PM) {
  PM.add(new DefUseChain());
}

static RegisterStandardPasses
    RegisterDefUseChainPass(PassManagerBuilder::EP_OptimizerLast,
                            registerDefUseChainPass);

static RegisterStandardPasses
    RegisterDefUseChainPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                             registerDefUseChainPass);
