#ifndef DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  template<typename T> class TrustedBulkRoundBadShuffler : public TrustedBulkRound, public Triggerable {
    public:
      explicit TrustedBulkRoundBadShuffler(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TrustedBulkRound(group_gen, creds, round_id, network, get_data, TCreateRound<T>)
      {
      }

      bool Triggered()
      {
        return TBadGuyCB<T>(GetShuffleRound().data());
      }
  };
}
}

#endif
