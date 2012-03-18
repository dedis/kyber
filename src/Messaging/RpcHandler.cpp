#include <QDataStream>
#include <QVariant>

#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"

#include "RpcHandler.hpp"

namespace Dissent {
namespace Messaging {
  const QString Request::NotificationType = QString("n");
  const QString Request::RequestType = QString("r");
  const QString Response::ResponseType = QString("p");

  RpcHandler::RpcHandler() :
    _current_id(1),
    _responder(new RequestResponder())
  {
    QObject::connect(_responder.data(),
        SIGNAL(RespondSignal(const Request &, const QVariant &)),
        this, SLOT(SendResponse(const Request &, const QVariant &)));

    QObject::connect(_responder.data(),
        SIGNAL(FailedSignal(const Request &, Response::ErrorTypes,
            const QString &, const QVariant &)),
        this,
        SLOT(SendFailedResponse(const Request &, Response::ErrorTypes,
            const QString &, const QVariant &)));
  }

  RpcHandler::~RpcHandler()
  {
  }

  void RpcHandler::Timeout(const int &id)
  {
    qDebug() << "Timed out:" << id << _requests.contains(id);
    if(!_requests.contains(id) || !_requests[id]->TimeoutCapable()) {
      return;
    }

    qDebug() << "Pushing timeout message";

    QSharedPointer<RequestState> state = _requests[id];
    _requests.remove(id);

    QVariantList msg = Response::Failed(id, Response::Timeout, "Local timeout");
    Response response(state->GetSender(), msg);
    state->GetResponseHandler()->RequestComplete(response);
  }

  void RpcHandler::HandleData(const QSharedPointer<ISender> &from,
      const QByteArray &data)
  {
    QVariantList container;
    QDataStream stream(data);
    stream >> container;

    HandleData(from, container);
  }

  void RpcHandler::HandleData(const QSharedPointer<ISender> &from,
      const QVariantList &container)
  {
    if(container.size() < 2) {
      return;
    }
    
    QString type = container.at(0).toString();
    if(type == Request::RequestType ||
        type == Request::NotificationType)
    {
      HandleRequest(Request(_responder, from, container));
    } else if(type == Response::ResponseType) {
      HandleResponse(Response(from, container));
    } else {
      qDebug() << "Received an unknown Rpc type:" << type;
    }
  }

  void RpcHandler::HandleRequest(const Request &request)
  {
    int id = request.GetId();
    if(id <= 0) {
      qWarning() << "RpcHandler: Request: Invalid ID, from: " <<
        request.GetFrom()->ToString();
      return;
    }

    QString method = request.GetMethod();
    QSharedPointer<RequestHandler> cb = _callbacks[method];
    if(cb.isNull()) {
      qDebug() << "RpcHandler: Request: No such method: " << method <<
        ", from: " << request.GetFrom()->ToString();
      SendFailedResponse(request, Response::InvalidMethod,
          QString("No such method: " + method));
      return;
    }

    qDebug() << "RpcHandler: Request " << request.GetId()  << "Method:" <<
      method << ", from:" << request.GetFrom()->ToString();
    cb->MakeRequest(request);
  }

  void RpcHandler::HandleResponse(const Response &response)
  {
    int id = response.GetId();
    if(id == 0) {
      qWarning() << "RpcHandler: Response: No ID, from" <<
        response.GetFrom()->ToString();
      return;
    }

    QSharedPointer<RequestState> state = _requests[id];
    if(!state) {
      qWarning() << "RpcHandler: Response: No handler for" << id;
      return;
    }

    if(state->GetSender() != response.GetFrom()) {
      qDebug() << "Received a response from a different source than " <<
        "the path the request was sent by.  Sent by:" <<
        state->GetSender()->ToString() << "Received by:" <<
        response.GetFrom()->ToString();
      // Eventually we need to not allow this behavior, but that means making
      // better equality comparator
    }

    state->StopTimer();
    _requests.remove(id);
    state->GetResponseHandler()->RequestComplete(response);
  }

  void RpcHandler::SendNotification(const QSharedPointer<ISender> &to,
      const QString &method, const QVariant &data)
  {
    int id = IncrementId();
    QVariantList container = Request::BuildNotification(id, method, data);

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;

    qDebug() << "RpcHandler: Sending notification" << id << "for" << method <<
      "to" << to->ToString();
    to->Send(msg);
  }

  int RpcHandler::SendRequest(const QSharedPointer<ISender> &to,
      const QString &method, const QVariant &data,
      const QSharedPointer<ResponseHandler> &cb, bool timeout)
  {
    int id = IncrementId();
    qint64 ctime = Utils::Time::GetInstance().MSecsSinceEpoch();

    TimerCallback *callback = new TimerCallback(this, &RpcHandler::Timeout, id);
    Utils::TimerEvent timer = Utils::Timer::GetInstance().QueueCallback(callback,
        TimeoutDelta);

    _requests[id] = QSharedPointer<RequestState>(
        new RequestState(to, cb, ctime, timer, timeout));
    QVariantList container = Request::BuildRequest(id, method, data);

    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    qDebug() << "RpcHandler: Sending request" << id << "for" << method <<
      "to" << to->ToString();
    to->Send(msg);
    return id;
  }

  void RpcHandler::SendResponse(const Request &request, const QVariant &data)
  {
    QVariantList container = Response::Build(request.GetId(), data);
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    qDebug() << "RpcHandler: Sending response" << request.GetId() <<
      "to" << request.GetFrom()->ToString();
    request.GetFrom()->Send(msg);
  }

  void RpcHandler::SendFailedResponse(const Request &request,
      Response::ErrorTypes error, const QString &reason,
      const QVariant &error_data)
  {
    QVariantList container = Response::Failed(request.GetId(), error,
        reason, error_data);
    QByteArray msg;
    QDataStream stream(&msg, QIODevice::WriteOnly);
    stream << container;
    qDebug() << "RpcHandler: Sending failed response" << request.GetId() <<
      "to" << request.GetFrom()->ToString();
    request.GetFrom()->Send(msg);
  }

  int RpcHandler::IncrementId()
  {
    return _current_id++;
  }

  bool RpcHandler::Register(const QString &name,
      const QSharedPointer<RequestHandler> &cb)
  {
    if(_callbacks.contains(name)) {
      return false;
    }

    _callbacks[name] = cb;
    return true;
  }

  bool RpcHandler::Register(const QString &name, const QObject *obj,
      const char *method)
  {
    if(_callbacks.contains(name)) {
      return false;
    }

    _callbacks[name] =
      QSharedPointer<RequestHandler>(new RequestHandler(obj, method));
    return true;
  }

  bool RpcHandler::Unregister(const QString &name)
  {
    QSharedPointer<RequestHandler> cb = _callbacks.value(name);
    if(cb.isNull()) {
      return false;
    }

    _callbacks.remove(name);
    return true;
  }
}
}
