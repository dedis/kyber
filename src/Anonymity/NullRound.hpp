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
       * @param clients the list of clients in the round
       * @param servers the list of servers in the round
       * @param ident this participants private information
       * @param nonce Unique round id (nonce)
       * @param overlay handles message sending
       * @param get_data requests data to share during this session
       */
      explicit NullRound(const Identity::Roster &clients,
          const Identity::Roster &servers,
          const Identity::PrivateIdentity &ident,
          const QByteArray &nonce,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          Messaging::GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~NullRound() {}

      inline virtual QString ToString() const { return "NullRound " + GetNonce().toBase64(); }

      /**
       * Handle a data message from a remote peer
       * @param from The remote sender
       * @param msg The message
       */
      virtual void ProcessPacket(const Connections::Id &from, const QByteArray &msg);

    protected:
      /**
       * Called when the NullRound is started
       */
      virtual void OnStart();

    private:
      /**
       * Don't receive from a remote peer more than once...
       */
      QVector<QByteArray> m_received;
      int m_msgs;
  };
}
}

#endif
