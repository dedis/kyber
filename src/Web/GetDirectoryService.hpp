#ifndef DISSENT_WEB_GET_DIRECTORY_SERVICE_GUARD
#define DISSENT_WEB_GET_DIRECTORY_SERVICE_GUARD

#include <QObject>
#include <QByteArray>
#include <QFile>
#include <QTextStream>
#include "WebService.hpp"

namespace Dissent {
namespace Web {

  class GetDirectoryService: public WebService {
    public:
      explicit GetDirectoryService(const QString &path);

      virtual ~GetDirectoryService();

      /**
       * Called to handle the incoming request
       * @param request the incoming request
       * @param response used to respond to the rqeuest
       */
      virtual void HandleRequest(QHttpRequest *request, QHttpResponse *response);

    private:
      QString _webpath; 
      static const QString _file_name;
  };

}
}
#endif
