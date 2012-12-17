#include "Anonymity/Round.hpp"

#include "SessionService.hpp"

namespace Dissent {
namespace Web {
  SessionService::SessionService(SessionManager &sm) :
    m_sm(sm)
  {
  }

  void SessionService::HandleRequest(QHttpRequest *,
      QHttpResponse *response)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantHash data;

    bool session_active = !session.isNull();
    data["session"] = session_active;
    data["session_id"] = "";
    data["round"] = false;
    data["round_id"] = "";

    if(session_active) {
      data["session_id"] = session->GetSessionId().ToString();
      QSharedPointer<Dissent::Anonymity::Round> round =
        session->GetCurrentRound();
      if(round) {
        data["round"] = true;
        data["round_id"] = round->GetRoundId().ToString();
      } 
    }

    SendJsonResponse(response, data);
  }
}
}
