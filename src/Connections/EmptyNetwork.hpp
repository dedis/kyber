#ifndef DISSENT_ANONYMITY_EMPTY_NETWORK_H_GUARD
#define DISSENT_ANONYMITY_EMPTY_NETWORK_H_GUARD

#include <QSharedPointer>
#include "Network.hpp"

namespace Dissent {
namespace Anonymity {
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
      virtual void SetHeaders(const QVariantMap &) {}
 
      /**
       * Does nothing
       */
      virtual QVariantMap GetHeaders()
      {
        static QVariantMap hash;
        return hash;
      }

      /**
       * Does nothing
       */
      virtual void SendNotification(QVariantMap &, const Id &) {}

      /**
       * Does nothing
       */
      virtual void SendRequest(QVariantMap &, const Id &, Callback *) {}

      /**
       * Does nothing
       */
      virtual Connection *GetConnection(const Id &) { return 0;}

      /**
       * Does nothing
       */
      virtual void Broadcast(const QByteArray &) {}

      /**
       * Does nothing
       */
      virtual void Send(const QByteArray &, const Id &) {}

    private:
      EmptyNetwork() {}
      Q_DISABLE_COPY(EmptyNetwork)
  };
}
}

#endif
