#ifndef DISSENT_MESSAGING_REQUEST_HANDLER_H_GUARD
#define DISSENT_MESSAGING_REQUEST_HANDLER_H_GUARD

#include <QObject>

#include "Request.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Used to create a request callback
   */
  class RequestHandler : public QObject {
    Q_OBJECT

    public:
      /**
       * Destructor
       */
      virtual ~RequestHandler() {}

      inline void MakeRequest(const Request &request) const
      {
        emit MakeRequestSignal(request);
      }

    signals:
      void MakeRequestSignal(const Request &request) const;
  };
}
}

#endif
