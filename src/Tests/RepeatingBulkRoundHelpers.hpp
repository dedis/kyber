#ifndef DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  template<typename T> class RepeatingBulkRoundBadShuffler : public RepeatingBulkRound, public Triggerable {
    public:
      RepeatingBulkRoundBadShuffler(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        RepeatingBulkRound(group_gen, creds, round_id, network, get_data, TCreateRound<T>)
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
