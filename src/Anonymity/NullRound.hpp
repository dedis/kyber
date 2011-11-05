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
          const ConnectionTable &ct, RpcHandler &rpc, 
          const QByteArray &data = DefaultData);

      /**
       * Destructor
       */
      virtual ~NullRound() {}

      /**
       * A callback (function pointer) used for creating a round
       * @param group The anonymity group
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param data Data to share this session
       */
      inline static Round *CreateRound(const Group &group, const Id &local_id,
          const Id &session_id, const ConnectionTable &ct, RpcHandler &rpc, 
          const QByteArray &data)
      {
        return new NullRound(group, local_id, session_id, ct, rpc, data);
      }

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
       * The data if any to share
       */
      const QByteArray _data;

      /**
       * Don't start twice...
       */
      bool _started;

      /**
       * Don't receive from a remote peer more than once...
       */
      QList<Id> _received_from;
  };
}
}

#endif
