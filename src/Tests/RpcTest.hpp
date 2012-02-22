#include "DissentTest.hpp"
#include <QDebug>

namespace Dissent {
namespace Tests {
  class TestRpc {
    public:
      void Add(RpcRequest &request)
      {
        RpcContainer msg = request.GetMessage();

        bool ok;
        int x = msg.value("x").toInt(&ok);
        if(!ok) {
          request.Respond(RpcResponse::Failed(QString("X is invalid")));
          return;
        }

        int y = msg.value("y").toInt(&ok);
        if(!ok) {
          request.Respond(RpcResponse::Failed(QString("Y is invalid")));
          return;
        }

        RpcContainer response;
        response["sum"] = x + y;
        request.Respond(response);
      }
  };

  class TestRpcResponse {
    public:
      TestRpcResponse() : _response(RpcContainer(), 0)
      {
      }

      void HandleResponse(RpcRequest &response)
      {
        _response = static_cast<RpcResponse &>(response);
      }

      int GetValue() { return _response.GetMessage()["sum"].toInt(); }
      RpcResponse GetResponse() { return _response; }
    private:
      RpcResponse _response;
  };
}
}
