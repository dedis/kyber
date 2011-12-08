#include "RoundIdService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  RoundIdService::RoundIdService(QSharedPointer<Node> node) :
    SessionWebService(node)
  {
  }

  void RoundIdService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantMap map;

    bool session_active = !session.isNull();
    map["active"] = false;
    map["id"] = "";

    if(session_active) {
      QSharedPointer<Dissent::Anonymity::Round> round =
        session->GetCurrentRound();

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

