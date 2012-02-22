#include "RpcResponse.hpp"

namespace Dissent {
namespace Messaging {
  const QString RpcResponse::ErrorField = QString("e");
  const QString RpcResponse::LocalErrorField = QString("l");
  const QString RpcResponse::SuccessField = QString("s");

  RpcResponse::RpcResponse(const QVariantMap &message, ISender *from) :
    RpcRequest(message, from)
  {
  }

  QVariantMap RpcResponse::Failed(const QString &reason, bool local)
  {
    QVariantMap message;
    message[ErrorField] = reason;
    message[LocalErrorField] = local;
    message[SuccessField] = false;
    return message;
  }

  void RpcResponse::Respond(QVariantMap)
  {
    throw std::logic_error("Cannot respond to a response.");
  }

  bool RpcResponse::Responded()
  {
    throw std::logic_error("Cannot respond to a response.");
  }
}
}
