#ifndef DISSENT_ANONYMITY_NULL_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NULL_ROUND_H_GUARD

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * A simple Dissent exchange.  Just broadcasts everyones message to everyone else
   */
  class NullRound : public Round {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param group_gen Generate groups for use during this round
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param get_data requests data to share during this session
       */
      NullRound(QSharedPointer<GroupGenerator> group_gen, const Id &local_id,
          const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc,
          GetDataCallback &get_data);

      /**
       * function pointer access to the constructor
       * @param group_gen Generate groups for use during this round
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param round_id unused
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param signing_key unused
       * @param get_data requests data to share during this session
       */
      inline static Round *Create(QSharedPointer<GroupGenerator> group_gen, 
          const Id &local_id, const Id &session_id, const Id &,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey>, GetDataCallback &get_data)
      {
        return new NullRound(group_gen, local_id, session_id, ct, rpc, get_data);
      }

      /**
       * Destructor
       */
      virtual ~NullRound() {}

      virtual bool Start();

      inline virtual QString ToString() const { return "NullRound"; }

    private:
      /**
       * Pushes the data into the subscribed Sink
       * @param data the data to push
       * @param id the source of the data
       */
      virtual void ProcessData(const QByteArray &data, const Id &id);

      /**
       * Don't receive from a remote peer more than once...
       */
      QList<Id> _received_from;
  };
}
}

#endif
