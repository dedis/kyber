
#include "Anonymity/Session.hpp"
#include "RoundIdService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  
  RoundIdService::RoundIdService(QSharedPointer<Session> session) :
    SessionWebService(session) {}

  RoundIdService::~RoundIdService() {}

  void RoundIdService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QVariantMap map;

    bool session_active = !_session.isNull();
    map["active"] = false;
    map["id"] = "";

    if(session_active) {
      QSharedPointer<Round> round = _session->GetCurrentRound();
      if(!round.isNull()) {
        map["active"] = true;
        map["id"] = round->GetRoundId().ToString();
      } 
    } 

    wrp->GetOutputData().setValue(map);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp);
    return;
  }

}
}
}

