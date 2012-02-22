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
      explicit RpcResponse(const RpcContainer &message, ISender *from);

      /**
       * Failed attempt
       * @param reason the reason for the failure
       * @param local did the error happen locally or on the remote member
       */
      static RpcContainer Failed(const QString &reason, bool local = false);

      virtual ~RpcResponse() {}

      /**
       * Not implemented, throws exception
       */
      virtual void Respond(RpcContainer);

      /**
       * Not implemented, throws exception
       */
      virtual bool Responded();

      inline bool Successful()
      {
        return (GetMessage().contains(SuccessField) == false) ||
          (GetMessage().value(SuccessField).toBool());
      }

      inline bool LocalError()
      {
        return (!Successful() && GetMessage().value(LocalErrorField).toBool());
      }

      inline QString ErrorReason()
      {
        if(Successful()) {
          return "Successful";
        }
        return GetMessage().value(ErrorField).toString();
      }

      static const QString ErrorField;
      static const QString LocalErrorField;
      static const QString ResponseType;
      static const QString SuccessField;
  };
}
}

#endif
