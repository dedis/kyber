#include "GetFileService.hpp"

namespace Dissent {
namespace Web {
namespace Services {

    GetFileService::GetFileService()
    {
      webpath = "./index.html";
    }

    // Get web page file
    void GetFileService::Handle(QSharedPointer<WebRequest> wrp)
    {

      QFile file(webpath);
      QString outputData;
      if (file.open(QIODevice::ReadOnly | QIODevice::Text)){
  outputData.append(file.readAll());
      }
  file.close();

      wrp->GetOutputData().setValue(outputData);
  wrp->SetStatus(HttpResponse::STATUS_OK);
      emit FinishedWebRequest(wrp, false);
    }
}
}
}

