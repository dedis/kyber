#ifndef DISSENT_SESSION_CLIENT_SESSION_H_GUARD
#define DISSENT_SESSION_CLIENT_SESSION_H_GUARD

#include <QHash>
#include <QSharedPointer>

#include "ClientRegister.hpp"
#include "Session.hpp"

#include "ClientServer/Overlay.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/Response.hpp"

namespace Dissent {
namespace Session {
  class ClientCommState;

  /**
   * Used to filter incoming messages across many sessions.
   */
  class ClientSession : public Session {
    Q_OBJECT

    friend ClientCommState;
    friend QSharedPointer<ClientSession> MakeSession<ClientSession>(
      const QSharedPointer<ClientServer::Overlay> &,
      const QSharedPointer<Crypto::AsymmetricKey> &,
      const QSharedPointer<Crypto::KeyShare> &,
      Anonymity::CreateRound);

    public:
      /**
       * Deconstructor
       */
      virtual ~ClientSession();

    protected:
      /**
       * Constructor
       * @param overlay used to pass messages to other participants
       * @param my_key local nodes private key
       * @param keys public keys for all participants
       * @param create_round callback for creating rounds
       */
      explicit ClientSession(
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Crypto::AsymmetricKey> &my_key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          Anonymity::CreateRound create_round);

      /**
       * New incoming connection
       * @param con the connection
       */
      virtual void HandleConnection(const QSharedPointer<Connections::Connection> &con);
  };
}
}

#endif
