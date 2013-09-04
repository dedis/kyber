#include <QtCore>
#if QT_VERSION >= QT_VERSION_CHECK(5, 0, 0)
#include <QUrlQuery>
#endif

#include "GetDirectoryService.hpp"

namespace Dissent {
namespace Web {
  GetDirectoryService::GetDirectoryService(const QString &path) :
    _webpath(path)
  {
  }

  GetDirectoryService::~GetDirectoryService()
  {
  }

  const QString GetDirectoryService::_file_name = "file";

  void GetDirectoryService::HandleRequest(QHttpRequest *request,
      QHttpResponse *response)
  {
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    QString filename = request->url().queryItemValue(_file_name);
#else
    QString filename = QUrlQuery(request->url()).queryItemValue(_file_name);
#endif
    if(filename.isEmpty()) {
      filename = "index.html";
    }

    QFile file(_webpath + "/" + filename);
    if(!file.exists()) {
      SendNotFound(response);
      return;
    }

    QByteArray outputData;
    if(file.open(QIODevice::ReadOnly)){
      outputData = file.readAll();
    }
    file.close();

    SendResponse(response, outputData);
  }
}
}
