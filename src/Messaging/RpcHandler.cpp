#include "RpcHandler.hpp"
#include <iostream>
#include <QtCore/qdatastream.h>

namespace Dissent {
namespace Messaging {
  RpcHandler::RpcHandler() : _current_id(1)
  {
  }

  RpcHandler::~RpcHandler()
  {
    foreach(Callback *cb, _callbacks) {
      delete cb;
    }
  }

  void RpcHandler::HandleData(const QByteArray& data, ISender *from)
  {
    RpcContainer message;
    QDataStream stream(data);
    stream >> message;

    if(message.empty()) {
      return;
    }

    QString type = message[RpcRequest::TypeField].toString();
    if(type == RpcRequest::RequestType || type == RpcRequest::NotificationType) {
      HandleRequest(message, from);
    } else if(type == RpcResponse::ResponseType) {
      HandleResponse(message, from);
    } else {
      qDebug() << "Received an unknown Rpc type:" << type;
    }
  }

  void RpcHandler::HandleRequest(RpcContainer& request, ISender *from)
  {
    QString method = request[RpcRequest::MethodField].toString();
    if(method.isEmpty()) {
      qWarning() << "RpcHandler: Request: No method, from: " << from->ToString();
      return;
    }

    int id = request[RpcRequest::IdField].toInt();
    if(id == 0) {
      qWarning() << "RpcHandler: Request: No ID, from: " << from->ToString();
      return;
    }

    RpcRequest rr(request, from);
    Callback *cb = _callbacks[method];
    if(cb == 0) {
      qDebug() << "RpcHandler: Request: No such method: " << method << ", from: " << from->ToString();
      rr.Respond(RpcResponse::Failed(QString("No such method: " + method)));
      return;
    }

    qDebug() << "RpcHandler: Request: Method:" << method << ", from:" << from->ToString();
    cb->Invoke(rr);
  }

  void RpcHandler::HandleResponse(RpcContainer& response, ISender *from)
  {
    int id = response[RpcRequest::IdField].toInt();
    if(id == 0) {
      qWarning() << "RpcHandler: Response: No ID, from " << from->ToString();
      return;
    }

    Callback *cb = _requests[id];
    if(cb == 0) {
      qWarning() << "RpcHandler: Response: No handler for " << id;
      return;
    }

    _requests.remove(id);

    RpcResponse rr(response, from);
    RpcRequest rreq = *(dynamic_cast<RpcRequest *>(&rr));
    cb->Invoke(rreq);
  }

  void RpcHandler::SendNotification(RpcContainer& notification, ISender *to)
  {
    if(!notification.contains(RpcRequest::MethodField)) {
      throw std::logic_error("No RPC method defined");
    }

    notification[RpcRequest::IdField] = IncrementId();
    notification[RpcRequest::TypeField] = RpcRequest::NotificationType;
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << notification;
    to->Send(data);
  }

  int RpcHandler::SendRequest(RpcContainer& request, ISender *to, Callback* cb)
  {
    if(!request.contains(RpcRequest::MethodField)) {
      throw std::logic_error("No RPC method defined");
    }

    int id = IncrementId();
    request[RpcRequest::IdField] = id;
    _requests[id] = cb;
    request[RpcRequest::TypeField] = RpcRequest::RequestType;
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << request;
    to->Send(data);
    return id;
  }

  int RpcHandler::IncrementId()
  {
    int id = _current_id++;
    return id;
  }

  bool RpcHandler::Register(Callback *cb, QString name)
  {
    if(_callbacks.contains(name)) {
      return false;
    }

    _callbacks[name] = cb;
    return true;
  }

  bool RpcHandler::Unregister(QString name)
  {
    return _callbacks.remove(name) != 0;
  }
}
}
