#ifndef DISSENT_WEB_WEB_SERVICE_GUARD
#define DISSENT_WEB_WEB_SERVICE_GUARD

#include <QObject>
#include <QSharedPointer>

#include "qhttprequest.h"
#include "qhttpresponse.h"
#include "json.h"

namespace Dissent {
namespace Web {
  /**
   * WebService is the abstract base class representing the logic for
   * processing a WebRequest. 
   */
  class WebService {
    public:
      virtual ~WebService();

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response) = 0;

    protected:
      QByteArray BuildJsonResponse(const QVariant &response, bool &success);
      void SendJsonResponse(QHttpResponse *response, const QVariant &data);
      void SendResponse(QHttpResponse *response, const QByteArray &data);
      void SendNotFound(QHttpResponse *response);
  };
}
}

#endif
