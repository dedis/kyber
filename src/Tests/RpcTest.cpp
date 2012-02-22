#include "DissentTest.hpp"

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
    rpc0.Register(new RpcMethod<TestRpc>(&test0, &TestRpc::Add), "add");

    QVariantMap request;
    request["method"] = "add";
    request["x"] = 3;
    request["y"] = 6;

    TestRpcResponse test1;
    RpcMethod<TestRpcResponse> cb = RpcMethod<TestRpcResponse>(&test1, &TestRpcResponse::HandleResponse);
    EXPECT_EQ(0, test1.GetValue());
    rpc1.SendRequest(request, &to_ms0, &cb);
    EXPECT_EQ(9, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());
    EXPECT_FALSE(test1.GetResponse().LocalError());

    request["y"] = "Haha";
    rpc1.SendRequest(request, &to_ms0, &cb);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    EXPECT_FALSE(test1.GetResponse().LocalError());

    request["x"] = "Haha";
    rpc1.SendRequest(request, &to_ms0, &cb);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    EXPECT_FALSE(test1.GetResponse().LocalError());

    request["x"] = 8;
    request["y"] = 2;
    rpc1.SendRequest(request, &to_ms0, &cb);
    EXPECT_EQ(10, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());
    EXPECT_FALSE(test1.GetResponse().LocalError());

    request["method"] = "Haha";
    rpc1.SendRequest(request, &to_ms0, &cb);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    EXPECT_FALSE(test1.GetResponse().LocalError());
  }
}
}
