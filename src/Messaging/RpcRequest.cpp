#include "RpcRequest.hpp"

namespace Dissent {
namespace Messaging {
  RpcRequest::RpcRequest(const QVariantMap &message, ISender *from) :
    _data(new RpcRequestData(message, from))
  {
  }

  void RpcRequest::Respond(QVariantMap response)
  {
    if(GetMessage()["type"].toString() == "notification") {
      qWarning() << "Cannot Respond on a notification";
      return;
    }

    if(_data->Responded) {
      qWarning() << "Cannot respond more than once.";
      return;
    }

    _data->Responded = true;
    response["id"] = GetMessage()["id"];
    response["type"] = "response";

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << response;

    GetFrom()->Send(data);
  }
}
}
