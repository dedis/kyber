#ifndef DISSENT_WEB_GET_FILE_SERVICE_GUARD
#define DISSENT_WEB_GET_FILE_SERVICE_GUARD

#include <QObject>
#include <QByteArray>
#include <QFile>
#include <QTextStream>
#include "WebService.hpp"

namespace Dissent {
namespace Web {

  class GetFileService: public WebService {
    public:
      explicit GetFileService(const QString &path);

      virtual ~GetFileService();

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);

    private:
      QString _webpath; 
  };

}
}
#endif
