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
    QString filename = request->url().queryItemValue(_file_name);
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
