#ifndef DISSENT_RPC_HANDLER_H_GUARD
#define DISSENT_RPC_HANDLER_H_GUARD

#include <stdexcept>

#include <QByteArray>
#include <QDebug>
#include <QHash>
#include <QString>
#include <QtCore/qdatastream.h>

#include "ISender.hpp"
#include "ISink.hpp"
#include "RpcMethod.hpp"
#include "RpcRequest.hpp"
#include "RpcResponse.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Rpc mechanism assumes a reliable sending mechanism
   */
  class RpcHandler : public ISink {
    public:
      /**
       * The constructor
       */
      RpcHandler();

      /**
       * The destructor
       */
      ~RpcHandler();

      /**
       * Handle an incoming Rpc request
       * @param data serialized request message
       * @param from a return path to the requestor
       */
      virtual void HandleData(const QByteArray &data, ISender *from);

      /**
       * Send a notification -- a request without expecting a response
       * @param notification message for the remote side
       * @param to path to destination
       */
      void SendNotification(QVariantMap &notification, ISender *to);

      /**
       * Send a request
       * @param request message for the remote side
       * @param to path to destination
       * @param cb function to call when returning
       */
      void SendRequest(QVariantMap &request, ISender *to, Callback* cb);

      /**
       * Send a response for a request
       * @param response the data for the remote side
       * @param to path to destination
       * @param request the original request
       */
      void SendResponse(QVariantMap &response, ISender *to, QVariantMap &request);

      /**
       * Register a callback
       * @param cb Method callback to register
       * @param name The string to match it with
       */
      bool Register(Callback *cb, QString name);

      /**
       * Unregister a callback
       * @param name name of method to remove
       */
      bool Unregister(QString name);

    private:

      /**
       * Handle an incoming request
       * @param request the request
       * @param from the remote sending party
       */
      void HandleRequest(QVariantMap &request, ISender *from);

      /**
       * Handle an incoming response
       * @param response the response
       * @param from the remote sending party
       */
      void HandleResponse(QVariantMap &response, ISender *from);

      /**
       * Returns the _current_id and increments it to the next
       */
      inline int IncrementId();

      /**
       * Maps a string to a method to call
       */
      QHash<QString, Callback *> _callbacks;

      /**
       * Maps id to a callback method to handle responses
       */
      QHash<int, Callback *> _requests;

      /**
       * Next request id
       */
      int _current_id;
  };
}
}

#endif
