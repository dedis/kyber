#ifndef DISSENT_WEB_ECHO_SERVICE_GUARD
#define DISSENT_WEB_ECHO_SERVICE_GUARD

#include <QtCore>
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
#include <QUrlQuery>
#endif

#include <QByteArray> 
#include <QList>

#include "MessageWebService.hpp"

namespace Dissent {
namespace Web {
  /** 
   * Web service for echoing the body of the requester
   */
  class EchoService : public WebService {
    public:
      explicit EchoService()
      {
      }

      virtual ~EchoService() {}

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response)
      {
        if(request->method() == QHttpRequest::HTTP_POST) {
          SendResponse(response, request->body());
        } else {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
          QByteArray rmsg = request->url().encodedQuery();
#else
          QByteArray rmsg = request->url().query(QUrl::FullyEncoded).toLatin1();
#endif
          SendResponse(response, rmsg);
        }
      }
  };

}
}

#endif
