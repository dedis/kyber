#include "Anonymity/Round.hpp"

#include "SessionService.hpp"

namespace Dissent {
namespace Web {
  SessionService::SessionService(
      const QSharedPointer<Session::Session> &session) :
    m_session(session)
  {
  }

  void SessionService::HandleRequest(QHttpRequest *,
      QHttpResponse *response)
  {
    QSharedPointer<Session::Session> session = GetSession();
    QVariantHash data;

    QSharedPointer<Dissent::Anonymity::Round> round = session->GetRound();
    if(round) {
      data["round"] = true;
      data["round_id"] = round->GetNonce().toBase64();
    } else {
      data["round"] = false;
    }

    SendJsonResponse(response, data);
  }
}
}
