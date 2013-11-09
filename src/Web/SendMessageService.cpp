#include "Utils/Serialization.hpp"
#include "SendMessageService.hpp"

namespace Dissent {
namespace Web {
  SendMessageService::SendMessageService(
      const QSharedPointer<Session::Session> &session) :
    SessionService(session)
  {
  }

  SendMessageService::~SendMessageService()
  {
  }

  void SendMessageService::HandleRequest(QHttpRequest *request,
      QHttpResponse *response)
  {
    QByteArray bytes = request->body();
    QByteArray header(8, 0);
    Utils::Serialization::WriteInt(bytes.size(), header, 0);
    GetSession()->Send(header + bytes);

    SendJsonResponse(response, true);
  }
}
}

