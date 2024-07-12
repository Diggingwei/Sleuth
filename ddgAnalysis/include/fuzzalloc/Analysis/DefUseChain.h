//===-- DefUseChain.h - Static def-use analysis -----------------*- C++ -*-===//
///
/// \file
/// Perform a static def-use chain analysis
///
//===----------------------------------------------------------------------===//

#ifndef DEF_USE_CHAINS_H
#define DEF_USE_CHAINS_H

#include <llvm/Pass.h>
#include <llvm/Support/JSON.h>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"

namespace llvm {
class DebugLoc;
class DIVariable;
class Instruction;
class Value;
} // namespace llvm

namespace SVF {
class BVDataPTAImpl;
class VFGNode;
} // namespace SVF

/// A variable definition
struct DefSite {
  DefSite(const SVF::VFGNode *, const llvm::DIVariable *,
          const llvm::DebugLoc *, const int EdgeLevel);

  bool operator==(const DefSite &Other) const { return Node == Other.Node; }

  template <typename H> friend H AbslHashValue(H Hash, const DefSite &Def) {
    return H::combine(std::move(Hash), Def.Node);
  }

  const SVF::VFGNode *Node;
  const llvm::Value *Val;
  const llvm::DIVariable *DIVar;
  const llvm::DebugLoc *Loc;
  const int Level;
};

/// A variable use
struct UseSite {
  UseSite(const SVF::VFGNode *, const int EdgeLevel);

  bool operator==(const UseSite &Other) const { return Node == Other.Node; }

  template <typename H> friend H AbslHashValue(H Hash, const UseSite &Use) {
    return H::combine(std::move(Hash), Use.Node);
  }

  const SVF::VFGNode *Node;
  const int Level;
  const llvm::Value *Val;
  const llvm::DebugLoc &Loc;
};

struct BugInformation {
    std::string BugType;  //create the information of bug type
    std::string BugOpt;   //create the infromation of bug option, READ or WRITE
    std::string BugBit;   //create the information of bit, where to read or write
    std::map<std::string, std::tuple<std::string, std::string, std::string, std::string>> BugInfo;  //create the information of target bug

    BugInformation(std::string _BugType, std::string _BugOpt, std::string _BugBit, std::map<std::string, std::tuple<std::string, std::string, std::string, std::string>> _BugInfo){
        this->BugType = _BugType;
        this->BugOpt = _BugOpt;
        this->BugBit = _BugBit;
        this->BugInfo = _BugInfo;
    }
};

/// Static def-use chain analysis
class DefUseChain : public llvm::ModulePass {
public:
  using DefSet = absl::flat_hash_set<DefSite>;
  using UseSet = absl::flat_hash_set<UseSite>;
  using DefUseMap = absl::flat_hash_map<DefSite, UseSet>;

  static char ID;
  DefUseChain() : llvm::ModulePass(ID) {}
  virtual ~DefUseChain();

  virtual void getAnalysisUsage(llvm::AnalysisUsage &) const override;
  virtual bool runOnModule(llvm::Module &) override;

  const DefUseMap &getDefUseChains() const { return DefUses; }

private:
  SVF::BVDataPTAImpl *WPA;
  DefUseMap DefUses;
};

// JSON helpers
llvm::json::Value toJSON(const DefSite &);
llvm::json::Value toJSON(const UseSite &);
llvm::json::Value toJSON(const DefUseChain::UseSet &);

#endif // DEF_USE_CHAINS_H
