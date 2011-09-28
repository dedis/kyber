#include "RpcRequest.hpp"

namespace Dissent {
namespace Messaging {
  RpcRequest::RpcRequest(const QVariantMap &message, ISender *from) :
    Message(message), From(from), _responded(false)
  {
  }

  void RpcRequest::Respond(QVariantMap &response)
  {
    if(Message["type"].toString() == "notification") {
      throw std::logic_error("Notification cannot be replied to");
    }

    if(_responded) {
      throw std::logic_error("Responded more than once.");
    }

    _responded = true;
    response["id"] = Message["id"];
    response["type"] = "response";

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << response;

    From->Send(data);
  }

  bool RpcRequest::Responded()
  {
    return _responded;
  }
}
}
