#ifndef DISSENT_ANONYMITY_NULL_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NULL_ROUND_H_GUARD

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  class NullRound : public Round {
    Q_OBJECT

    public:
      NullRound(const Id &local_id, const Group &group, ConnectionTable &ct,
          RpcHandler *rpc, const Id &round_id);
      NullRound(const Id &local_id, const Group &group, ConnectionTable &ct,
          RpcHandler *rpc, const Id &round_id, const QByteArray &data);
      virtual void Start();

    private:
      virtual void ProcessData(const QByteArray &data, const Id &id);
      const QByteArray _data;
      QList<Id> _received_from;
  };
}
}

#endif
