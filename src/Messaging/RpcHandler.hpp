#ifndef DISSENT_MESSAGING_RPC_HANDLER_H_GUARD
#define DISSENT_MESSAGING_RPC_HANDLER_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QHash>
#include <QObject>
#include <QString>
#include <QSharedPointer>

#include "Utils/TimerCallback.hpp"
#include "Utils/TimerEvent.hpp"

#include "ISender.hpp"
#include "ISinkObject.hpp"
#include "Request.hpp"
#include "RequestHandler.hpp"
#include "RequestResponder.hpp"
#include "Response.hpp"
#include "ResponseHandler.hpp"

namespace Dissent {
namespace Messaging {
  class RequestState;

  /**
   * Rpc mechanism assumes a reliable sending mechanism
   */
  class RpcHandler : public ISinkObject {
    Q_OBJECT

    public:
      typedef Utils::TimerMethod<RpcHandler, int> TimerCallback;
      static const int TimeoutDelta = 60000;

      inline static QSharedPointer<RpcHandler> GetEmpty()
      {
        static QSharedPointer<RpcHandler> handler(new RpcHandler());
        return handler;
      }

      /**
       * The constructor
       */
      explicit RpcHandler();

      /**
       * The destructor
       */
      virtual ~RpcHandler();

      /**
       * Handle an incoming Rpc request
       * @param from a return path to the requestor
       * @param data serialized request message
       */
      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data);

      /**
       * Handle an incoming Rpc request
       * @param from a return path to the requestor
       * @param container deserialized request message
       */
      void HandleData(const QSharedPointer<ISender> &from,
          const QVariantList &container);

      /**
       * Send a request
       * @param to the destination for the notification
       * @param method the remote method
       * @param data the input data for that method
       * @returns the id of the request so that the callback can be cancelled
       */
      void SendNotification(const QSharedPointer<ISender> &to,
          const QString &method, const QVariant &data);

      /**
       * Send a request
       * @param to the destination for the request
       * @param method the remote method
       * @param data the input data for that method
       * @param callback called when the request is complete
       * @param timeout specifies whether or not to let the request timeout.
       * It is a temporary parameter that will be phased out in the future,
       * all future Rpc Methods should be implemented with potential timeouts
       * in mind.
       * @returns the id of the request so that the callback can be cancelled
       */
      int SendRequest(const QSharedPointer<ISender> &to, const QString &method,
          const QVariant &data, const QSharedPointer<ResponseHandler> &callback,
          bool timeout = false);

      /**
       * Register a callback
       * @param name The string to match it with
       * @param cb Method callback to register
       */
      bool Register(const QString &name,
          const QSharedPointer<RequestHandler> &cb);

      /**
       * Register a callback into the specified object
       * @param name The string to match it with
       * @param obj with the method name
       * @param method name of method
       */
      bool Register(const QString &name, const QObject *obj,
          const char *method);

      /**
       * Unregister a callback
       * @param name name of method to remove
       */
      bool Unregister(const QString &name);

      /**
       * Used to cancel handling a request result
       * @param id the id of the request
       */
      bool CancelRequest(int id)
      {
        return _requests.remove(id) != 0;
      }

    public slots:
      /**
       * Send a response for a request
       * @param request the original request
       * @param data the data for the remote side
       */
      void SendResponse(const Request &request, const QVariant &data);

      /**
       * Send a response for a request
       * @param request the original request
       * @param reason the reason for the failure
       */
      void SendFailedResponse(const Request &request,
          Response::ErrorTypes error, const QString &reason,
          const QVariant &error_data = QVariant());

    private:
      void StartTimer();
      void Timeout(const int &);

      /**
       * Handle an incoming request
       * @param request the request
       */
      void HandleRequest(const Request &request);

      /**
       * Handle an incoming response
       * @param response the response
       */
      void HandleResponse(const Response &response);

      /**
       * Returns the _current_id and increments it to the next
       */
      inline int IncrementId();

      /**
       * Maps a string to a method to call
       */
      QHash<QString, QSharedPointer<RequestHandler> > _callbacks;

      /**
       * Maps id to a callback method to handle responses
       */
      QMap<int, QSharedPointer<RequestState> > _requests;

      /**
       * Next request id
       */
      int _current_id;

      /**
       * Used to asynchronously respond to requests
       */
      QSharedPointer<RequestResponder> _responder;

      QSharedPointer<TimerCallback> _timer_callback;
      Utils::TimerEvent _next_call;
  };

  class RequestState {
    public:
      RequestState(const QSharedPointer<ISender> sender,
          const QSharedPointer<ResponseHandler> &res_h,
          qint64 start_time, const Utils::TimerEvent &timer, bool timeout) :
        _sender(sender),
        _res_h(res_h),
        _start_time(start_time),
        _timer(timer),
        _timeout(timeout)
      {
      }

      ~RequestState()
      {
        _timer.Stop();
      }

      inline QSharedPointer<ISender> GetSender() const { return _sender; }

      inline QSharedPointer<ResponseHandler> GetResponseHandler() const
      {
        return _res_h;
      }

      inline qint64 GetStartTime() const { return _start_time; }

      void StopTimer() { _timer.Stop(); }

      bool TimeoutCapable() const { return _timeout; }

    private:
      QSharedPointer<ISender> _sender;
      QSharedPointer<ResponseHandler> _res_h;
      qint64 _start_time;
      Utils::TimerEvent _timer;
      bool _timeout;
  };
}
}

#endif
