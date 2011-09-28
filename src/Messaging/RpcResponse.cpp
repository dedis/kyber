#include "RpcResponse.hpp"

namespace Dissent {
namespace Messaging {
  RpcResponse::RpcResponse(const QVariantMap &message, ISender *from) :
    RpcRequest(message, from)
  {
  }

  void RpcResponse::Respond(QVariantMap &)
  {
    throw std::logic_error("Cannot respond to a response.");
  }

  bool RpcResponse::Responded()
  {
    throw std::logic_error("Cannot respond to a response.");
  }
}
}
