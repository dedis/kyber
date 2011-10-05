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
       * Constructor without data
       * @param local_id The local peers id
       * @param group The anonymity group
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param session_id Session this round represents
       */
      NullRound(const Id &local_id, const Group &group, const ConnectionTable &ct,
          RpcHandler *rpc, const Id &session_id);

      /**
       * Constructor with data
       * @param local_id The local peers id
       * @param group The anonymity group
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param session_id Session this round represents
       * @param data Data to share this session
       */
      NullRound(const Id &local_id, const Group &group, const ConnectionTable &ct,
          RpcHandler *rpc, const Id &session_id, const QByteArray &data);

      virtual void Start();

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
