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
#include <llvm/Support/Debug.h>
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/ASanStackFrameLayout.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
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

using namespace llvm; 

enum StoreType { declaration, modification};

struct FlowWriteInstruction {
    BasicBlock* BB;
    Instruction* I;
    //Value* WrittenVar;
    //Value* WhatWeAreWriting;
    //std::vector<Value*>* WhatWeAreDepending;
    StoreType Type;

    FlowWriteInstruction(BasicBlock* _BB, Instruction* _I, StoreType _T) {
        this->BB = _BB;
        this->I = _I;
        this->Type = _T;
    }

    FlowWriteInstruction(struct FlowWriteInstruction* S) {
        this->BB = S->BB;
        this->I = S->I;
        this->Type = S->Type;
    }
};

struct BugInformation {
    std::string BugType;  //create the information of bug type
    std::string BugOpt;   //create the infromation of bug option, READ or WRITE
    std::string BugBit;   //create the information of bit, where to read or write
    std::map<std::string, std::tuple<std::string, std::string, std::string>> BugInfo;  //create the information of target bug

    BugInformation(std::string _BugType, std::string _BugOpt, std::string _BugBit, std::map<std::string, std::tuple<std::string, std::string, std::string>> _BugInfo){
        this->BugType = _BugType;
        this->BugOpt = _BugOpt;
        this->BugBit = _BugBit;
        this->BugInfo = _BugInfo;
    }
};

struct Use_stat{
    std::string file;
    std::string func;
    std::string line;
    std::string level;

    Use_stat(std::string& f, std::string& c, std::string& l, std::string& e)
        : file(f), func(c), line(l), level(e){}
};

struct Def_stat{
    std::string def_name;
    std::string file;
    std::string func;
    std::string line;
    std::string level;

    Def_stat(std::string& d, std::string& f, std::string& c, std::string& l, std::string& e)
        : def_name(d), file(f), func(c), line(l), level(e){} 
};

struct DefUse_Chain{
    Def_stat* Def_site;
    std::vector<Use_stat*> Use_set;

    DefUse_Chain(Def_stat* _Def_site, std::vector<Use_stat*> _Use_set) : Def_site(_Def_site), Use_set(_Use_set){} 
};

//Debug

void debug_instruction(Instruction* I);
//void debug_DDG(std::map<CustomDDGNode*, std::vector<CustomDDGNode*>> graph);

//Other util methods

bool* isReachableByStore(std::vector<FlowWriteInstruction*>* From, Instruction* To, DominatorTree* DT, LoopInfo* LI, unsigned* ConsideredStores);
bool isPredecessorBB(Instruction* Src, Instruction *To);
