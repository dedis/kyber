#include "GetFileService.hpp"

namespace Dissent {
namespace Web {
  GetFileService::GetFileService(const QString &path) :
    _webpath(path)
  {
  }

  GetFileService::~GetFileService()
  {
  }

  void GetFileService::HandleRequest(QHttpRequest *,
      QHttpResponse *response)
  {
    QFile file(_webpath);
    if(!file.exists()) {
      SendNotFound(response);
      return;
    }

    QByteArray outputData;
    if(file.open(QIODevice::ReadOnly)) {
      outputData = file.readAll();
    }
    file.close();

    SendResponse(response, outputData);
  }
}
}
