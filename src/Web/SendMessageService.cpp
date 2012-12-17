#include "Utils/Serialization.hpp"
#include "SendMessageService.hpp"

namespace Dissent {
namespace Web {
  SendMessageService::SendMessageService(SessionManager &sm) :
    SessionService(sm)
  {
  }

  SendMessageService::~SendMessageService()
  {
  }

  void SendMessageService::HandleRequest(QHttpRequest *request,
      QHttpResponse *response)
  {
    QSharedPointer<Session> session = GetSession();
    QVariant data;

    if(session) {
      QByteArray bytes = request->body();
      QByteArray header(8, 0);
      Utils::Serialization::WriteInt(bytes.size(), header, 0);
      session->Send(header + bytes);

      data = true;
    } else {
      data = false;
    }

    SendJsonResponse(response, data);
  }
}
}

