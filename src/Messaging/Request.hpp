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
      /**
       * Constructor -- allows empty constructions
       * @param responder a callback object for the response
       * @param from the sender of the request
       * @param container the information about the request
       */
      Request(const QSharedPointer<RequestResponder> &responder =
            QSharedPointer<RequestResponder>(),
          const QSharedPointer<ISender> &from = QSharedPointer<ISender>(),
          const QVariantList &container = QVariantList()) :
        _responder(responder),
        _from(from),
        _container(container)
      {
        while(_container.size() < 4) {
          _container.append(QVariant());
        }
        Q_ASSERT(_container.size() == 4);
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
      inline void Failed(Response::ErrorTypes error, const QString &reason,
          const QVariant &error_data = QVariant()) const
      {
        _responder->Failed(*this, error, reason, error_data);
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
