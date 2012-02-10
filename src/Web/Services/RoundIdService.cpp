#include "Anonymity/Round.hpp"

#include "RoundIdService.hpp"

namespace Dissent {
namespace Web {
namespace Services {
  RoundIdService::RoundIdService(SessionManager &sm) :
    SessionWebService(sm)
  {
  }

  void RoundIdService::Handle(QSharedPointer<WebRequest> wrp)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantHash hash;

    bool session_active = !session.isNull();
    hash["active"] = false;
    hash["id"] = "";

    if(session_active) {
      QSharedPointer<Dissent::Anonymity::Round> round =
        session->GetCurrentRound();

      if(!round.isNull()) {
        hash["active"] = true;
        hash["id"] = round->GetRoundId().ToString();
      } 
    } 

    wrp->GetOutputData().setValue(hash);
    wrp->SetStatus(HttpResponse::STATUS_OK);
    emit FinishedWebRequest(wrp, true);
    return;
  }
}
}
}

