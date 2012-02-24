#ifndef DISSENT_MESSAGING_REQUEST_H_GUARD
#define DISSENT_MESSAGING_REQUEST_H_GUARD

#include <QSharedPointer>
#include <QVariant>

#include "RequestResponder.hpp"

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Represents the state of an  Request
   */
  class Request {
    public:
      Request(const QSharedPointer<RequestResponder> &responder,
          const QSharedPointer<ISender> &from,
          const QVariantList &container) :
        _responder(responder),
        _from(from),
        _container(container)
      {
        while(_container.size() < 4) {
          _container.append(QVariant());
        }
      }

      inline static QVariantList BuildNotification(int id,
          const QString &method, const QVariant &data)
      {
        QVariantList container;
        container.append(NotificationType);
        container.append(id);
        container.append(method);
        container.append(data);
        return container;
      }

      inline static QVariantList BuildRequest(int id,
          const QString &method, const QVariant &data)
      {
        QVariantList container;
        container.append(RequestType);
        container.append(id);
        container.append(method);
        container.append(data);
        return container;
      }

      /**
       * Pathway back to the remote peer
       */
      inline QSharedPointer<ISender> GetFrom() const { return _from; }

      /**
       * Notification / Request
       */
      inline QString GetType() const { return _container.at(0).toString(); }

      /**
       * Unique Id from sender
       */
      inline int GetId() const { return _container.at(1).toInt(); }

      /**
       * Method called
       */
      inline QString GetMethod() const { return _container.at(2).toString(); }

      /**
       * Method data
       */
      inline QVariant GetData() const { return _container.at(3); };

      /**
       * Respond to the request
       */
      inline void Respond(const QVariant &data) const
      {
        _responder->Respond(*this, data);
      }

      /**
       * Response to the request with a failure
       */
      inline void Failed(const QString &reason) const
      {
        _responder->Failed(*this, reason);
      }

      static const QString NotificationType;
      static const QString RequestType;

    private:
      QSharedPointer<RequestResponder> _responder;
      QSharedPointer<ISender> _from;
      QVariantList _container;
  };
}
}

#endif
