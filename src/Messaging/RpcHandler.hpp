#ifndef DISSENT_MESSAGING_RPC_HANDLER_H_GUARD
#define DISSENT_MESSAGING_RPC_HANDLER_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QHash>
#include <QObject>
#include <QString>
#include <QSharedPointer>

#include "ISender.hpp"
#include "ISinkObject.hpp"
#include "Request.hpp"
#include "RequestHandler.hpp"
#include "RequestResponder.hpp"
#include "Response.hpp"
#include "ResponseHandler.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Rpc mechanism assumes a reliable sending mechanism
   */
  class RpcHandler : public ISinkObject {
    Q_OBJECT

    public:
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
       * @returns the id of the request so that the callback can be cancelled
       */
      int SendRequest(const QSharedPointer<ISender> &to, const QString &method,
          const QVariant &data, const QSharedPointer<ResponseHandler> &callback);

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
       */
      bool Register(const QString &name, const QObject *obj,
          const char *method);

      /**
       * Unregister a callback
       * @param name name of method to remove
       */
      bool Unregister(const QString &name);

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
      QHash<int, QSharedPointer<ResponseHandler> > _requests;

      /**
       * Next request id
       */
      int _current_id;

      /**
       * Used to asynchronously respond to requests
       */
      QSharedPointer<RequestResponder> _responder;
  };
}
}

#endif
