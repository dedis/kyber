#ifndef DISSENT_MESSAGING_REQUEST_RESPONDER_H_GUARD
#define DISSENT_MESSAGING_REQUEST_RESPONDER_H_GUARD

#include <QObject>

class QVariant;

namespace Dissent {
namespace Messaging {
  class Request;

  /**
   * Used to create a request callback
   */
  class RequestResponder : public QObject {
    Q_OBJECT

    public:
      /**
       * Destructor
       */
      virtual ~RequestResponder() {}

      inline void Respond(const Request &request, const QVariant &data) const
      {
        emit RespondSignal(request, data);
      }

      inline void Failed(const Request &request, const QString &reason) const
      {
        emit FailedSignal(request, reason);
      }

    signals:
      void RespondSignal(const Request &request, const QVariant &data) const;
      void FailedSignal(const Request &request, const QString &reason) const;
  };
}
}

#endif
