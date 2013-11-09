#ifndef DISSENT_CLIENT_SERVER_FORWARDER_H_GUARD
#define DISSENT_CLIENT_SERVER_FORWARDER_H_GUARD

#include <QObject>

#include "Connections/Id.hpp"
#include "Connections/IForwarder.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/RpcHandler.hpp"

#include "Overlay.hpp"

namespace Dissent {
namespace Messaging {
  class Request;
}

namespace Connections {
  class Connection;
  class ForwardingSender;
}

namespace ClientServer {

  /**
   * Does the hard work in forwarding packets over the overlay
   */
  class Forwarder : public QObject, public Connections::IForwarder {
    Q_OBJECT

    public:
      /**
       * Static constructor
       */
      static QSharedPointer<Forwarder> Get(
          const QSharedPointer<Overlay> &overlay)
      {
        QSharedPointer<Forwarder> rf(new Forwarder(overlay));
        rf->SetSharedPointer(rf);
        return rf;
      }

      /**
       * Destructor
       */
      virtual ~Forwarder();

      /**
       * Returns a sender that can be used to communicate via the overlay
       */
      QSharedPointer<Messaging::ISender> GetSender(const Connections::Id &to);

      /**
       * The forwarding sender should call this to forward a message along
       */
      virtual void Forward(const Connections::Id &to, const QByteArray &data);

      QSharedPointer<Connections::IForwarder> GetSharedPointer()
      {
         return m_shared.toStrongRef();
      }

    private:
      /**
       * Constructor
       * @param overlay
       */
      Forwarder(const QSharedPointer<Overlay> &overlay);
  
      void Send(const QString &from,
          const QSharedPointer<Connections::Connection> &con,
          const Connections::Id &to,
          const QByteArray &data);

      /**
       * Helper function for forwarding data -- does the hard work
       */
      void Forward(const QString &from,
          const Connections::Id &to,
          const QByteArray &data);

      void SetSharedPointer(const QSharedPointer<Connections::IForwarder> &shared)
      {
        m_shared = shared.toWeakRef();
      }

      QWeakPointer<Connections::IForwarder> m_shared;
      QSharedPointer<Overlay> m_overlay;
      
    private slots:
      /**
       * Incoming data for forwarding
       */
      virtual void IncomingData(const Messaging::Request &notification);

  };

}
}

#endif
