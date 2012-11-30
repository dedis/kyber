#include "GetDirectoryService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  GetDirectoryService::GetDirectoryService(const QString &path) :
    _webpath(path)
  {
  }

  const QString GetDirectoryService::_file_name = "file";

  void GetDirectoryService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QUrl url = wrp->GetRequest().GetUrl();
    QString filename = url.queryItemValue(_file_name);
    if(filename.isEmpty()) {
      filename = "index.html";
    }

    QFile file(_webpath + "/" + filename);
    qDebug() << _webpath + "/" + filename;
    if(!file.exists()) {
      wrp->SetStatus(HttpResponse::STATUS_NOT_FOUND);
      emit FinishedWebRequest(wrp, false);
      return;
    }

    QString outputData;
    if(file.open(QIODevice::ReadOnly | QIODevice::Text)){
      outputData = file.readAll();
    }
    file.close();

    wrp->GetOutputData().setValue(outputData);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, false);
  }
}
}
}
