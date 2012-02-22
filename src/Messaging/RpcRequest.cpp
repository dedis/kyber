#include "RpcRequest.hpp"
#include "RpcResponse.hpp"

namespace Dissent {
namespace Messaging {
  const QString RpcRequest::IdField = QString("i");
  const QString RpcRequest::NotificationType = QString("n");
  const QString RpcRequest::RequestType = QString("r");
  const QString RpcRequest::TypeField = QString("t");
  const QString RpcRequest::MethodField = QString("method");

  RpcRequest::RpcRequest(const RpcContainer &message, ISender *from) :
    _data(new RpcRequestData(message, from))
  {
  }

  void RpcRequest::Respond(RpcContainer response)
  {
    if(GetMessage()[TypeField].toString() == NotificationType) {
      qWarning() << "Cannot Respond on a notification";
      return;
    }

    if(_data->Responded) {
      qWarning() << "Cannot respond more than once.";
      return;
    }

    _data->Responded = true;
    response[IdField] = GetMessage()[IdField];
    response[RpcRequest::TypeField] = RpcResponse::ResponseType;

    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << response;

    GetFrom()->Send(data);
  }
}
}
