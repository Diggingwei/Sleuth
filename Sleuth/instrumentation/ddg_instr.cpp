#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Analysis/MemoryBuiltins.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/BinaryFormat/MachO.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Comdat.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Use.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Verifier.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/MC/MCSectionMachO.h"
#include "llvm/Pass.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/ScopedPrinter.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

//#include "WPA/WPAPass.h"

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <climits>
#include <iomanip>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <tuple>
#include <fstream>
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "ddg_utils.h"
#include "config.h"

#include "json.h"

#define MAX_DEPTH 3
#define MIN_FCN_SIZE 1
#define VAR_NAME_LEN 264

//#define MAP_SIZE 65536
#define ALL_BIT_SET (MAP_SIZE - 1)
//#define MAP_SIZE 255

//#define INTERPROCEDURAL 1   	// unset if you want only intraprocedural ret values management BUT
#define  LOAD_INSTR           // considers loads as stores

//#define DEBUG 1               // set if you want debug prints enabled


#define AFL_SR(s) (srandom(s))
#define AFL_R(x) (random() % (x))

#ifdef DEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

using namespace llvm;
using namespace std;
using namespace Json;
//using namespace svf;

Module* M2;

class DDGInstrModulePass : public ModulePass {


private:

    // delet some char
    std::string DealString(Json::Value initial_Value){
        Json::FastWriter writer;
        std::size_t pos = 0;
        std::string initial_String = writer.write(initial_Value);

        while ((pos = initial_String.find_first_of(" \n\r\t\"", pos)) != std::string::npos){
            initial_String.erase(pos, 1);
        }

        return initial_String;
    }

    // parser def-use chain in json
    void JSONAnalysis(std::string json_path, std::vector<Def_stat*> &_def_site, std::vector<DefUse_Chain*> &_def_use, std::set<std::string> &_file_collect){
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::ifstream file(json_path);  //open json
        std::string Errs;
        Json::FastWriter writer;

        bool openJson = Json::parseFromStream(builder, file, &root, &Errs); //parse json
        if (!openJson){
            errs() << "parse failed!\n";
        }

        for (int i = 0; i < root.size(); i++){
            std::vector<Use_stat*> Use_collect;
            // Def site collect
            std::string def_name = DealString(root[i][0][0]);
            Json::Value def_info = root[i][0][1];
            std::string file_str = DealString(def_info[0]);
            std::string func_str = DealString(def_info[1]);
            std::string row_str = DealString(def_info[2]);
            std::string col_str = DealString(def_info[3]);
            std::string line_str = row_str + ":" + col_str;
            std::string level_str = DealString(def_info[4]);
            _file_collect.insert(file_str);
            Def_stat *Def_single = new Def_stat(def_name, file_str, func_str, line_str, level_str);
            _def_site.push_back(Def_single);

            // Use site collect
            for (int j = 0; j < root[i][1].size(); j++){
                Json::Value use_info = root[i][1][j];
                std::string file_str = DealString(use_info[0]);
                std::string func_str = DealString(use_info[1]);
                std::string row_str = DealString(use_info[2]);
                std::string col_str = DealString(use_info[3]);
                std::string line_str = row_str + ":" + col_str;
                std::string level_str = DealString(use_info[4]);
                _file_collect.insert(file_str);
                Use_stat *Use_single = new Use_stat(file_str, func_str, line_str, level_str);
                Use_collect.push_back(Use_single);
            }
            //Collect Def_use_chain
            DefUse_Chain *DefUse = new DefUse_Chain(Def_single, Use_collect);
            _def_use.push_back(DefUse);
        }

    }

public:

    static char ID;

    std::string init_filename = "/src/vulnInfo/target.json";
    std::string debug_dir = "/src/vulnInfo/debug";
    std::vector<Def_stat*> def_site;
    std::vector<DefUse_Chain*> def_use; 
    std::set<std::string> file_collect;

    explicit DDGInstrModulePass() : ModulePass(ID) {}
    void getAnalysisUsage(AnalysisUsage &AU) const override {
        AU.addRequired<LoopInfoWrapperPass>();
        AU.addRequired<DominatorTreeWrapperPass>();
        AU.addRequired<PostDominatorTreeWrapperPass>();
    }

    StringRef getPassName() const override {
        return "DDGInstrModulePass";
    }

	bool doInitialization(Module &M) override {
		//LLVMContext* C = &(M.getContext());
		return true;
	}

    //Module* M2;

    bool runOnModule(Module &M) override {

        LLVMContext &C = M.getContext();        //include global data
        IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
        IntegerType *Int16Ty = IntegerType::getInt16Ty(C);
        IntegerType *Int8Ty = IntegerType::getInt8Ty(C);
        IntegerType *Int1Ty = IntegerType::getInt1Ty(C);

        M2 = &M;

        //judge should be instrumented
        ConstantInt *Zero = ConstantInt::get(Int8Ty, 0);
        ConstantInt *One = ConstantInt::get(Int8Ty, 1);
        unsigned int instrumentedLocations = 0;
        std::string sourceFileName = M.getSourceFileName();

        std::map<BasicBlock*, ConstantInt*> BlocksLocs;
        std::map<BasicBlock*, llvm::Value*> VisitedBlocks;
        ConstantInt *Visited = ConstantInt::get(Int16Ty, 0xff);
        ConstantInt *NonVisited = ConstantInt::get(Int16Ty, 0);

        std::map<BasicBlock*, std::set<BasicBlock*>> IncomingEdges;             //From the def to use
        std::map<BasicBlock*, std::set<BasicBlock*>> OutcomingEdges;            //From the use to def
        std::map<std::string, std::vector<std::string>> DefSite_Collect;
        std::map<std::string, BasicBlock*> LocMapping; //The loc -> basicblock
        std::map<BasicBlock*, GlobalVariable*> DefVisitedBlocks;  //verser def site

        std::map<BasicBlock*, uint16_t> BasicBlockLevel;     //record the level of basicblock

        char* name = nullptr;
        ConstantInt* CurLoc;
        unsigned BBCounter = 0;

        unsigned bb_count = 0;
        unsigned int cur_loc = 0;
        uint32_t map_size = TARGET_MAP;

        struct timeval tv;
        struct timezone tz;
        unsigned int rand_seed;

        errs() << sourceFileName << "\n";
        /*Setup random() so we Actually Random(TM) outputs from AFL_SR()*/
        gettimeofday(&tv, &tz);
        rand_seed = tv.tv_sec ^ tv.tv_usec ^ getpid();
        AFL_SR(rand_seed);

        const char* path_value = std::getenv("SLEUTH_PATH");
        if (path_value != nullptr) {
            outs() << "SLEUTH_PATH: " << path_value << "\n";
        } else {
            outs() << "Not set SLEUTH_PATH" << "\n";
        }

        std::string json_filename = path_value + init_filename;
        std::string debug_filename = path_value + debug_dir;

        /*set afl label*/

        //GlobalVariable* AFLMapPtr = M.getGlobalVariable("__afl_area_ptr");
        
        GlobalVariable *TBMapPtr = (GlobalVariable*)M.getOrInsertGlobal("__target_bb_ptr", PointerType::get(Int32Ty, 0),[]() -> GlobalVariable* {
            return new GlobalVariable(*M2, PointerType::get(IntegerType::getInt32Ty(M2->getContext()), 0), false,
                         GlobalValue::ExternalLinkage, 0, "__target_bb_ptr");
        });
        
        /*
        if (AFLMapPtr == nullptr){
            AFLMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false, GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");
        }
        */

        /*Get target def site to $def_site, get def-use chain to $def_use*/
        JSONAnalysis(json_filename, def_site, def_use, file_collect);
        
        //exetence file
        std::set<std::string>::iterator it;
        int down_flag = 0;
        for (it = file_collect.begin(); it != file_collect.end(); ++it){
            if (sourceFileName.find(*it) != std::string::npos){
                down_flag = 1;
            }
        }
        if (down_flag == 0){
            return true;
        }

        std::ofstream bb_debug(debug_filename + "/bb_debug.txt");
        std::ofstream func_debug(debug_filename + "/func_debug.txt");

        /*Collect def site*/
        for (Def_stat* Def : def_site){
            DefSite_Collect[Def->func].push_back(Def->line);
        }

        /*Collect Line Mapping*/
        for (auto &F : M){
            if (F.size() < MIN_FCN_SIZE) continue;

            for (auto &BB : F){
                BBCounter++;
                for (auto &I :BB){
                    /*Search the target line's row and col*/
                    DILocation *Line = I.getDebugLoc();
                    unsigned int _row;
                    unsigned int _col;
                    std::string _tol;
                    if (Line){
                        _row = Line->getLine();
                        _col = Line->getColumn();
                        _tol = to_string(_row) + ":" + to_string(_col);
                        if (_tol != "0:0" && _tol != "null:null"){
                            LocMapping[_tol] = &BB;
                        }
                    }
                }
            }
        }

        //Mapping line to basicblock
        for (auto DU : def_use){
            BasicBlock* Def_first;
            auto Use_Info = DU->Use_set;
            auto Def_Info = DU->Def_site;

            /*traversal the def site*/
            std::string Def_line = Def_Info->line;
            std::string Def_file = Def_Info->file;
            std::string Def_level = Def_Info->level;
            //exetence file
            if (LocMapping.find(Def_line) != LocMapping.end() && sourceFileName.find(Def_file) != std::string::npos){
                Def_first = LocMapping[Def_line];

                //Give level to basicblock
                if (BasicBlockLevel.find(Def_first) != BasicBlockLevel.end()){
                    if (std::stoi(Def_level) < BasicBlockLevel[Def_first]){
                        BasicBlockLevel[Def_first] = std::stoi(Def_level);
                    }
                }else{
                    if (std::stoi(Def_level) > 255){
                        BasicBlockLevel[Def_first] = 255;
                    }
                    else{
                        BasicBlockLevel[Def_first] = std::stoi(Def_level);
                    } 
                }

                /*traversal the use site*/
                for (auto U : Use_Info){
                    std::string Use_line = U->line;
                    std::string Use_level = U->level;
                    BasicBlock* Use_first;
                    if (LocMapping.find(Use_line) != LocMapping.end()){
                        Use_first = LocMapping[Use_line];
                        if (Use_level == "null"){
                            continue;
                        }

                        //Give level to basicblock
                        if (BasicBlockLevel.find(Use_first) != BasicBlockLevel.end()){
                            if (std::stoi(Use_level) < BasicBlockLevel[Use_first]){
                                BasicBlockLevel[Use_first] = std::stoi(Use_level);
                            }
                        }else{
                            if (std::stoi(Use_level) > 255){
                                BasicBlockLevel[Use_first] = 255;
                            }else{
                                BasicBlockLevel[Use_first] = std::stoi(Use_level);
                            }
                        }

                        if (Def_first != Use_first){
                            IncomingEdges[Def_first].insert(Use_first);
                            OutcomingEdges[Use_first].insert(Def_first);
                        }  
                    }
                }
            }
        }

        // declear global variable for ever def site
        int num_count = 0;
        for (auto DefCom : IncomingEdges){
            std::string index = "myGlobal_" + to_string(num_count);
            GlobalVariable *GV = new GlobalVariable(M, Int16Ty, false, GlobalValue::ExternalLinkage, NonVisited, index);
            GV->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
            num_count++;

            DefVisitedBlocks[DefCom.first] = GV;
        }

        /*Instrment the def site in function*/

        for (auto &F : M){
            if (F.size() < MIN_FCN_SIZE) continue;
            std::string f_name = (F.getName()).str();

            BasicBlock& EntryBB = F.getEntryBlock();
            BasicBlock::iterator IP = EntryBB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));
            llvm::Value* IsCurrentBlockVisited;             //Visit use
            GlobalVariable* IsCurrentGlobalVisited;         //Visit def globalVariable

            for (auto &BB : F){
                bb_count++;
                if (IncomingEdges.find(&BB) == IncomingEdges.end() && OutcomingEdges.find(&BB) == OutcomingEdges.end()){
                    continue;
                }

                /*We store 255 to def site's variable, if it show in the entryBB of fuction*/
                if (IncomingEdges.find(&BB) != IncomingEdges.end()){
                    /*Tag variable assign*/
                    StoreInst* InitializeVisited;
                    if (&EntryBB == &BB){
                        IsCurrentGlobalVisited = DefVisitedBlocks[&BB];
                        InitializeVisited = IRB.CreateStore(Visited, IsCurrentGlobalVisited);
                        if (InitializeVisited){
                            InitializeVisited->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                        }
                        DefVisitedBlocks[&BB] = IsCurrentGlobalVisited;
                    }
                }

                /*We instrument the use site, and declear the variable, maybe it never be used in bitcode*/
                else if (OutcomingEdges.find(&BB) != OutcomingEdges.end()){
                    //outs() << "Analysis " << &BB << "\n";
                     /*Tag variable alloc*/
                    name = new char[VAR_NAME_LEN];
                    memset(name, 0, VAR_NAME_LEN);
                    snprintf(name, VAR_NAME_LEN, "my_var_%d", BBCounter++);

                    AllocaInst* AllocaIsCurrentlyBlockVisited = IRB.CreateAlloca(Int16Ty, nullptr, StringRef(name));
                    AllocaIsCurrentlyBlockVisited->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                    IsCurrentBlockVisited = static_cast<llvm::Value*>(AllocaIsCurrentlyBlockVisited);

                    /*Tag variable assign*/
                    StoreInst* InitializeVisited;
                    if (&EntryBB == &BB){
                        InitializeVisited = IRB.CreateStore(Visited, IsCurrentBlockVisited);
                    }else{
                        InitializeVisited = IRB.CreateStore(NonVisited, IsCurrentBlockVisited);
                    }
                    if (InitializeVisited){
                        InitializeVisited->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                    }
                    VisitedBlocks[&BB] = IsCurrentBlockVisited;
                }

                /*Generate the roll number for both def site and use site*/
                cur_loc = AFL_R(map_size);
                CurLoc = ConstantInt::get(Int16Ty, cur_loc);
                BlocksLocs[&BB] = CurLoc;
            }

            for (auto &BB :F){
                if (&BB == &EntryBB){
                    continue;
                }

                IP = BB.getFirstInsertionPt();
                IRBuilder<> IRB(&(*IP));
                
                if (IncomingEdges.find(&BB) != IncomingEdges.end()){
                    IsCurrentGlobalVisited = DefVisitedBlocks[&BB];
                    StoreInst* StoreIsVisited = IRB.CreateStore(Visited, IsCurrentGlobalVisited);
                    StoreIsVisited->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
                }
                else if(OutcomingEdges.find(&BB) != OutcomingEdges.end()){
                    IsCurrentBlockVisited = VisitedBlocks[&BB];
                    StoreInst* StoreIsVisited = IRB.CreateStore(Visited, IsCurrentBlockVisited);
                    StoreIsVisited->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                    /*We calculate the hash value in the use site, it judge if the def site has been gone through, and add its value to use site*/
                    llvm::Value* HashedLoc = nullptr;
                    for (std::set<BasicBlock*>::iterator it = OutcomingEdges[&BB].begin(); it != OutcomingEdges[&BB].end(); ++it){
                        GlobalVariable* isVisited = DefVisitedBlocks[*it];
                        ConstantInt* PotentiallyPreviousLoc = BlocksLocs[*it];
                        if (!isVisited || !PotentiallyPreviousLoc){
                            continue;
                        }
                        LoadInst* LoadIsVisited = IRB.CreateLoad(isVisited);
                        LoadIsVisited->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                        llvm::Value* PrevLocIfVisited = IRB.CreateAnd(LoadIsVisited, PotentiallyPreviousLoc);
                        CurLoc = BlocksLocs[&BB];
                        if (HashedLoc == nullptr){
                            HashedLoc = IRB.CreateXor(CurLoc, PrevLocIfVisited);
                        }else{
                            HashedLoc = IRB.CreateXor(HashedLoc, PrevLocIfVisited);
                        }
                    }
                    if (HashedLoc == nullptr){
                        continue;
                    }

                    /*now it likes AFL++, but future we want to use the new bitmap*/
                    HashedLoc = IRB.CreateZExt(HashedLoc, IRB.getInt32Ty());
                    //LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
                    LoadInst * MapPtr = IRB.CreateLoad(TBMapPtr);
                    MapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                    llvm::Value* MapPtrIdx = IRB.CreateGEP(MapPtr, HashedLoc);
                    LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
                    Counter->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                    uint16_t BB_level = BasicBlockLevel[&BB];
                    uint16_t BB_idx = instrumentedLocations + 1; 
                    uint32_t BB_value = (static_cast<uint32_t>(BB_idx) << 16) | BB_level;

                    //Distribution the level
                    ConstantInt *LevelScore = ConstantInt::get(Int32Ty, BB_value);

                    /*
                    llvm::Value *Incr = IRB.CreateAdd(Counter, One);
                    auto cf = IRB.CreateICmpEQ(Incr, Zero);
                    auto carry = IRB.CreateZExt(cf, Int8Ty);
                    Incr = IRB.CreateAdd(Incr, carry);
                    StoreInst* StoreMapPtr = IRB.CreateStore(Incr, MapPtrIdx);
                    */
                    StoreInst* StoreMapPtr = IRB.CreateStore(LevelScore, MapPtrIdx);
                    StoreMapPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));

                    std::string bb_name = BB.getName().str();
                    std::string func_name = F.getName().str();
                    const Instruction *top_inst = BB.getFirstNonPHIOrDbgOrLifetime();
                    std::string top_line = "0";
                    
                    if (top_inst){
                        DILocation *top_loc = top_inst->getDebugLoc();
                        if (top_loc){
                            top_line = to_string(top_loc->getLine());
                        }
                    }

                    instrumentedLocations++;

                    bb_debug << instrumentedLocations << "," << bb_name << "," << top_line << "," << to_string(BB_level) << "\n";
                    func_debug << instrumentedLocations << "," << func_name << "\n";

                }


            }
        }


        outs() << "DDG - Instrumented " << instrumentedLocations << " locations over a total of " << bb_count << " \t\n";
        return true;

    }

};

char DDGInstrModulePass::ID = 0;

static void registerDDGInstrPass(const PassManagerBuilder &,
                               legacy::PassManagerBase &PM) {

  PM.add(new DDGInstrModulePass());

}

static RegisterStandardPasses RegisterDDGInstrPass(
    PassManagerBuilder::EP_OptimizerLast, registerDDGInstrPass);

static RegisterStandardPasses RegisterDDGInstrPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerDDGInstrPass);

static RegisterPass<DDGInstrModulePass>
    X("ddg-instr", "DDGInstrPass",
      false,
      false
    );
