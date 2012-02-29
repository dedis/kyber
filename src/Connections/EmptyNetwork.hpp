#ifndef DISSENT_CONNECTIONS_EMPTY_NETWORK_H_GUARD
#define DISSENT_CONNECTIONS_EMPTY_NETWORK_H_GUARD

#include <QByteArray>
#include <QSharedPointer>
#include <QVariant>

#include "Network.hpp"

namespace Dissent {
namespace Messaging {
  class ResponseHandler;
}

namespace Connections {
  class Connection;
  class ConnectionManager;
  class Id;

  class EmptyNetwork : public Network {
    public:
      static QSharedPointer<Network> GetInstance()
      {
        static QSharedPointer<Network> net(new EmptyNetwork());
        return net;
      }

      /**
       * Virtual destructor
       */
      virtual ~EmptyNetwork() {}

      /**
       * Does nothing
       */
      inline virtual QString GetMethod() const { return QString(); }

      /**
       * Does nothing
       */
      inline virtual void SetMethod(const QString &) { }

      /**
       * Does nothing
       */
      virtual void SetHeaders(const QVariantHash &) { }
 
      /**
       * Does nothing
       */
      virtual QVariantHash GetHeaders() const
      {
        return QVariantHash();
      }

      /**
       * Does nothing
       */
      virtual QSharedPointer<Connection> GetConnection(const Id &) const
      {
        return QSharedPointer<Connection>();
      }

      /**
       * Does nothing
       */
      virtual QSharedPointer<ConnectionManager> GetConnectionManager() const
      {
       return QSharedPointer<ConnectionManager>();
      }

      /**
       * Does nothing
       */
      virtual void SendNotification(const Id &, const QString &,
          const QVariant &)
      {
      }

      /**
       * Does nothing
       */
      virtual void SendRequest(const Id &, const QString &,
          const QVariant &, QSharedPointer<ResponseHandler> &)
      {
      }

      /**
       * Does nothing
       */
      virtual void Broadcast(const QByteArray &)
      {
      }

      /**
       * Does nothing
       */
      virtual void Send(const Id &, const QByteArray &)
      {
      }

      /**
       * Returns a copy of this object
       */
      virtual Network *Clone() const
      {
        return new EmptyNetwork(*this);
      }

    private:
      explicit EmptyNetwork() {}
      EmptyNetwork(const EmptyNetwork &) {}
  };
}
}

#endif
