#ifndef DISSENT_MESSAGING_RESPONSE_H_GUARD
#define DISSENT_MESSAGING_RESPONSE_H_GUARD

#include <QSharedPointer>
#include <QVariant>

namespace Dissent {
namespace Messaging {
  class ISender;

  /**
   * Represents the state of an  Response
   */
  class Response {
    public:
      /**
       * Constructor
       * @param from The sender of the response
       * @param container The response message
       */
      Response(const QSharedPointer<ISender> &from,
          const QVariantList &container) :
        _from(from),
        _container(container)
      {
        while(_container.size() < 4) {
          _container.append(QVariant());
        }
      }

      /**
       * Helper function for building a data structure for a response
       * @param id unique id from the sender
       * @param data return value
       */
      inline static QVariantList Build(int id, const QVariant &data)
      {
        QVariantList container;
        container.append(ResponseType);
        container.append(id);
        container.append(true);
        container.append(data);
        return container;
      }

      /**
       * Helper function for building a data structure for a failed request
       * @param id unique id from the sender
       * @param reason reason for the failure
       */
      inline static QVariantList Failed(int id, const QString &reason)
      {
        QVariantList container;
        container.append(ResponseType);
        container.append(id);
        container.append(false);
        container.append(reason);
        return container;
      }

      /**
       * Pathway back to the remote peer
       */
      inline QSharedPointer<ISender> GetFrom() const { return _from; }

      /**
       * Notification / Response
       */
      inline QString GetType() const { return _container.at(0).toString(); }

      /**
       * Unique Id from sender
       */
      inline int GetId() const { return _container.at(1).toInt(); }

      /**
       * Successful?
       */
      inline bool Successful() const { return _container.at(2).toBool(); }

      /**
       * Return data
       */
      inline QVariant GetData() const { return _container.at(3); }

      /**
       * Returns the error string, if unsuccessful is true
       */
      inline QString GetError() const
      {
        if(Successful()) {
          return QString();
        }
        return _container.at(3).toString();
      }

      static const QString ResponseType;
    private:
      QSharedPointer<ISender> _from;
      QVariantList _container;
  };
}
}

#endif
