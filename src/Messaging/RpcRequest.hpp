#ifndef DISSENT_RPC_REQUEST_H_GUARD
#define DISSENT_RPC_REQUEST_H_GUARD

#include <stdexcept>

#include <QVariant>
#include <QtCore/qdatastream.h>

#include "ISender.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Represents the state of an Rpc Request
   */
  class RpcRequest {
    public:
      /**
       * Constructor
       */
      RpcRequest(const QVariantMap &message, ISender *from);

      /**
       * Response to a request
       * @param response encoded response for the remote peer
       */
      virtual void Respond(QVariantMap &response);

      /**
       * Was there a response sent yet?
       */
      virtual bool Responded();

      /**
       * The message sent from the remote peer
       */
      const QVariantMap Message;

      /**
       * Pathway back to the remote peer
       */
      ISender *const From;

    private:
      bool _responded;
  };
}
}

#endif
