#ifndef DISSENT_TESTS_TOLERANT_TREE_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_TOLERANT_TREE_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::Tolerant::TolerantTreeRound TolerantTreeRound;

  template<typename B, template <int> class S, int N> class TolerantTreeRoundBadKeyShuffler :
      public B, public Triggerable
  {
    public:
      explicit TolerantTreeRoundBadKeyShuffler(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        B(group, ident, round_id, network, get_data, TNCreateRound<S, N>)
      {
      }

      bool Triggered()
      {
        return TBadGuyCB<S<N> >(B::GetKeyShuffleRound().data());
      }
  };

}
}

#endif
