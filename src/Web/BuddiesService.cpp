#include "Anonymity/Round.hpp"
#include "Anonymity/Buddies/BuddyMonitor.hpp"

#include "BuddiesService.hpp"

namespace Dissent {
namespace Web {
  BuddiesService::BuddiesService(SessionManager &sm) :
    SessionService(sm)
  {
  }

  void BuddiesService::HandleRequest(QHttpRequest *,
      QHttpResponse *response)
  {
    QSharedPointer<Session> session = GetSession();
    QVariantHash data;

    bool session_active = !session.isNull();
    data["buddies"] = false;
    if(session_active) {
      QSharedPointer<Anonymity::Round> round =
        session->GetCurrentRound();
      if(round) {
        QSharedPointer<BuddyMonitor> bm = round->GetBuddyMonitor();
        if(bm) {
          data["buddies"] = true;
          QVariantList members;
          QVariantList pseudonyms;
          for(int idx = 0; idx < bm->GetCount(); idx++) {
            members.append(bm->GetMemberAnonymity(idx));
            pseudonyms.append(bm->GetNymAnonymity(idx));
          }

          QVariantHash result;
          data["members"] = members;
          data["nyms"] = pseudonyms;
        }
      }
    }

    SendJsonResponse(response, data);
  }
}
}
