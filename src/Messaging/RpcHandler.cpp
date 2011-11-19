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
    QVariantMap message;
    QDataStream stream(data);
    stream >> message;

    if(message.empty()) {
      return;
    }

    QString type = message["type"].toString();
    if(type == "request" || type == "notification") {
      HandleRequest(message, from);
    } else if(type == "response") {
      HandleResponse(message, from);
    } else {
    }
  }

  void RpcHandler::HandleRequest(QVariantMap& request, ISender *from)
  {
    QString method = request["method"].toString();
    if(method.isEmpty()) {
      qWarning() << "RpcHandler: Request: No method, from: " << from->ToString();
      return;
    }

    int id = request["id"].toInt();
    if(id == 0) {
      qWarning() << "RpcHandler: Request: No ID, from: " << from->ToString();
      return;
    }

    Callback *cb = _callbacks[method];
    if(cb == 0) {
      qWarning() << "RpcHandler: Request: No such method: " << method << ", from: " << from->ToString();
      return;
    }

    qDebug() << "RpcHandler: Request: Method:" << method << ", from:" << from->ToString();
    RpcRequest rr(request, from);
    cb->Invoke(rr);
  }

  void RpcHandler::HandleResponse(QVariantMap& response, ISender *from)
  {
    int id = response["id"].toInt();
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

  void RpcHandler::SendNotification(QVariantMap& notification, ISender *to)
  {
    if(!notification.contains("method")) {
      throw std::logic_error("No RPC method defined");
    }

    notification["id"] = IncrementId();
    notification["type"] = "notification";
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << notification;
    to->Send(data);
  }

  void RpcHandler::SendRequest(QVariantMap& request, ISender *to, Callback* cb)
  {
    if(!request.contains("method")) {
      throw std::logic_error("No RPC method defined");
    }

    int id = IncrementId();
    request["id"] = id;
    _requests[id] = cb;
    request["type"] = "request";
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);
    stream << request;
    to->Send(data);
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
