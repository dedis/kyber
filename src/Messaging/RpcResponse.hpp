#ifndef DISSENT_RPC_RESPONSE_H_GUARD
#define DISSENT_RPC_RESPONSE_H_GUARD

#include "RpcRequest.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Inherits a Request but prevents responding as such behavior makes no sense.
   */
  class RpcResponse : public RpcRequest {
    public:
      /**
       * Constructor
       */
      RpcResponse(const QVariantMap &message, ISender *from);

      virtual ~RpcResponse() {}

      /**
       * Not implemented, throws exception
       */
      virtual void Respond(QVariantMap &);

      /**
       * Not implemented, throws exception
       */
      virtual bool Responded();

    private:
      bool _responded;
  };
}
}

#endif
