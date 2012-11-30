#ifndef DISSENT_WEB_SERVICES_GET_DIRECTORY_SERVICE_GUARD
#define DISSENT_WEB_SERVICES_GET_DIRECTORY_SERVICE_GUARD

#include <QObject>
#include <QByteArray>
#include <QFile>
#include <QTextStream>
#include "WebService.hpp"

namespace Dissent {
namespace Web {
namespace Services {

  class GetDirectoryService: public WebService {
    public:
      explicit GetDirectoryService(const QString &path);

      virtual ~GetDirectoryService() {}

    private:
      /**
       * The main method for the web service. If the status code wrp->status
       * is not STATUS_OK, then the output data might not be set.
       * @param request to be handled
       */
      virtual void Handle(QSharedPointer<WebRequest> wrp);
      QString _webpath; 
      static const QString _file_name;
  };

}
}
}
#endif
