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
      static const QByteArray DefaultData;

      /**
       * Constructor
       * @param group The anonymity group
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param data Data to share this session
       */
      NullRound(const Group &group, const Id &local_id, const Id &session_id,
          const ConnectionTable &ct, RpcHandler &rpc, const QByteArray &data);

      /**
       * function pointer access to the constructor
       * @param group The anonymity group
       * @param active_group unused
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param round_id unused
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param signing_key unused
       * node in the group
       * @param data Data to share this session
       */
      inline static Round *Create(const Group &group, const Group &,
          const Id &local_id, const Id &session_id, const Id &,
          const ConnectionTable &ct, RpcHandler &rpc,
          QSharedPointer<AsymmetricKey>, const QByteArray &data)
      {
        return new NullRound(group, local_id, session_id, ct, rpc, data);
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
