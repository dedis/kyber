#ifndef DISSENT_CLIENT_SERVER_BROADCASTER_H_GUARD
#define DISSENT_CLIENT_SERVER_BROADCASTER_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Connections/Connection.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/Id.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/RpcHandler.hpp"

#include "Forwarder.hpp"
#include "Overlay.hpp"

namespace Dissent {
namespace ClientServer {
  /**
   * Creates a broadcast tree using the CSOverlay used internally by CSNetwork
   */
  class Broadcaster : public QObject {
    Q_OBJECT
    public:
      /**
       * Constructor
       */
      Broadcaster(const QSharedPointer<Overlay> &overlay,
          const QSharedPointer<Forwarder> &forwarder);

      /**
       * Destructor
       */
      virtual ~Broadcaster();

      /**
       * Send a notification to all group members
       * @param method The Rpc to call
       * @param data Data to be sent to all members
       */
      void Broadcast(const QString &method, const QVariant &data);

    private:
      inline QSharedPointer<Messaging::ISender> GetSender(const Connections::Id &to)
      {
        QSharedPointer<Messaging::ISender> sender =
          m_overlay->GetConnectionTable().GetConnection(to);
        if(!sender) {
          sender = m_forwarder->GetSender(to);
        }
        return sender;
      }

      QSharedPointer<Overlay> m_overlay;
      QSharedPointer<Forwarder> m_forwarder;

    private slots:
      void BroadcastHelper(const Messaging::Request &notification);
  };
}
}

#endif
