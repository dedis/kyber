#ifndef DISSENT_MESSAGING_REQUEST_RESPONDER_H_GUARD
#define DISSENT_MESSAGING_REQUEST_RESPONDER_H_GUARD

#include <QObject>

#include "Response.hpp"

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

      void Failed(const Request &request, Response::ErrorTypes error,
          const QString &reason, const QVariant &error_data) const
      {
        emit FailedSignal(request, error, reason, error_data);
      }

    signals:
      void RespondSignal(const Request &request, const QVariant &data) const;
      void FailedSignal(const Request &request, Response::ErrorTypes error,
          const QString &reason, const QVariant &error_data) const;
  };
}
}

#endif
