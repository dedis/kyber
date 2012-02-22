#include "RpcResponse.hpp"

namespace Dissent {
namespace Messaging {
  const QString RpcResponse::ErrorField = QString("e");
  const QString RpcResponse::LocalErrorField = QString("l");
  const QString RpcResponse::ResponseType = QString("p");
  const QString RpcResponse::SuccessField = QString("s");

  RpcResponse::RpcResponse(const RpcContainer &message, ISender *from) :
    RpcRequest(message, from)
  {
  }

  RpcContainer RpcResponse::Failed(const QString &reason, bool local)
  {
    RpcContainer message;
    message[ErrorField] = reason;
    message[LocalErrorField] = local;
    message[SuccessField] = false;
    return message;
  }

  void RpcResponse::Respond(RpcContainer)
  {
    throw std::logic_error("Cannot respond to a response.");
  }

  bool RpcResponse::Responded()
  {
    throw std::logic_error("Cannot respond to a response.");
  }
}
}
