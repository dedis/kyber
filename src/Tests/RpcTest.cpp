#include "DissentTest.hpp"

using namespace Dissent::Messaging;

namespace Dissent {
namespace Tests {
  TEST(Rpc, HelloWorld)
  {
    RpcHandler rpc0;
    MockSource ms0;
    ms0.SetSink(&rpc0);
    MockSender to_ms0(&ms0);

    RpcHandler rpc1;
    MockSource ms1;
    ms1.SetSink(&rpc1);
    MockSender to_ms1(&ms1);
    to_ms0.SetReturnPath(&to_ms1);
    to_ms1.SetReturnPath(&to_ms0);

    TestRpc test0;
    rpc0.Register(new RpcMethod<TestRpc>(test0, &TestRpc::Add), "add");

    QVariantMap request;
    request["method"] = "add";
    request["x"] = 3;
    request["y"] = 6;

    TestRpcResponse test1;
    RpcMethod<TestRpcResponse> cb = RpcMethod<TestRpcResponse>(test1, &TestRpcResponse::HandleResponse);
    EXPECT_EQ(-1, test1.value);
    rpc1.SendRequest(request, &to_ms0, &cb);
    EXPECT_EQ(9, test1.value);
  }
}
}
