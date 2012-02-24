#ifndef DISSENT_MESSAGING_RESPONSE_HANDLER_H_GUARD
#define DISSENT_MESSAGING_RESPONSE_HANDLER_H_GUARD

#include <QObject>

#include "Response.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Used to create a response callback
   */
  class ResponseHandler : public QObject {
    Q_OBJECT

    public:
      /**
       * Destructor
       */
      virtual ~ResponseHandler() {}

      /**
       * Called to initiate to pass the response to the actual handler
       * @param response the response to the request
       */
      void RequestComplete(const Response &response) const
      {
        emit RequestCompleteSignal(response);
      }

    signals:
      /**
       * Called when a response to a request comes back
       * @param response 
       */
      void RequestCompleteSignal(const Response &response) const;
  };
}
}

#endif
