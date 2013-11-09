#ifndef DISSENT_SESSION_SERVER_SESSION_H_GUARD
#define DISSENT_SESSION_SERVER_SESSION_H_GUARD

#include <QMap>
#include <QMetaEnum>
#include <QSharedPointer>

#include "Anonymity/Round.hpp"
#include "ClientServer/Overlay.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/ResponseHandler.hpp"
#include "Utils/TimerEvent.hpp"

#include "ClientRegister.hpp"
#include "ServerAgree.hpp"
#include "ServerEnlist.hpp"
#include "ServerInit.hpp"
#include "ServerQueued.hpp"
#include "Session.hpp"

namespace Dissent {
namespace Session {
  /**
   * The session code for a server process
   */
  class ServerSession : public Session {
    Q_OBJECT
    
    friend QSharedPointer<ServerSession> MakeSession<ServerSession>(
      const QSharedPointer<ClientServer::Overlay> &,
      const QSharedPointer<Crypto::AsymmetricKey> &,
      const QSharedPointer<Crypto::KeyShare> &,
      Anonymity::CreateRound);

    public:
      /**
       * Deconstructor
       */
      virtual ~ServerSession();

    protected:
      /**
       * Constructor
       * @param overlay used to pass messages to other participants
       * @param my_key local nodes private key
       * @param keys public keys for all participants
       * @param create_round callback for creating rounds
       */
      explicit ServerSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round);

    private:
      /**
       * New incoming connection
       * @param con the connection
       */
      virtual void HandleConnection(
          const QSharedPointer<Connections::Connection> &con);
  };
}
}

#endif
