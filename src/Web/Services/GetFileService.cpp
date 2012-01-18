#include "GetFileService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  GetFileService::GetFileService(const QString &path) :
    _webpath(path)
  {
  }

  // Get web page file
  void GetFileService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QFile file(_webpath);
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

