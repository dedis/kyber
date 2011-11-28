#include "DissentTest.hpp"
#include <QDebug>

namespace Dissent {
namespace Tests {
  class TestRpc {
    public:
      void Add(RpcRequest& request)
      {
        QVariantMap msg = request.GetMessage();
        int x = msg["x"].toInt();
        int y = msg["y"].toInt();
        QVariantMap response;
        response["sum"] = x + y;
        request.Respond(response);
      }
  };

  class TestRpcResponse {
    public:
      int value;

      TestRpcResponse() : value(-1) { }

      void HandleResponse(RpcRequest& response)
      {
        value = response.GetMessage()["sum"].toInt();
      }
  };
}
}
