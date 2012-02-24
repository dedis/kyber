#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Rpc, HelloWorld)
  {
    RpcHandler rpc0;
    QSharedPointer<MockSource> ms0(new MockSource());;
    ms0->SetSink(&rpc0);
    QSharedPointer<MockSender> to_ms0(new MockSender(ms0));

    RpcHandler rpc1;
    QSharedPointer<MockSource> ms1(new MockSource());;
    ms1->SetSink(&rpc1);
    QSharedPointer<MockSender> to_ms1(new MockSender(ms1));
    to_ms0->SetReturnPath(to_ms1);
    to_ms1->SetReturnPath(to_ms0);

    TestRpc test0;
    QSharedPointer<RequestHandler> req_h(new RequestHandler(&test0, "Add"));
    rpc0.Register("add", req_h);

    TestResponse test1;
    QSharedPointer<ResponseHandler> res_h(
        new ResponseHandler(&test1, "HandleResponse"));

    EXPECT_EQ(0, test1.GetValue());

    QVariantList data;
    data.append(3);
    data.append(6);
    rpc1.SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(9, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());
    EXPECT_EQ(test1.GetResponse().GetErrorType(), Response::NoError);
    qWarning() << test1.GetResponse().GetError() << test1.GetResponse().GetErrorType();

    data[1] = "Haha";
    rpc1.SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    EXPECT_EQ(test1.GetResponse().GetErrorType(), Response::InvalidInput);
    qWarning() << test1.GetResponse().GetError() << test1.GetResponse().GetErrorType();

    data[0] = "Haha";
    rpc1.SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    EXPECT_EQ(test1.GetResponse().GetErrorType(), Response::InvalidInput);
    qWarning() << test1.GetResponse().GetError() << test1.GetResponse().GetErrorType();

    data[0] = 8;
    data[1] = 2;
    rpc1.SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(10, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());
    EXPECT_EQ(test1.GetResponse().GetErrorType(), Response::NoError);
    qWarning() << test1.GetResponse().GetError() << test1.GetResponse().GetErrorType();

    rpc1.SendRequest(to_ms0, "Haha", data, res_h);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
    EXPECT_EQ(test1.GetResponse().GetErrorType(), Response::InvalidMethod);
    qWarning() << test1.GetResponse().GetError() << test1.GetResponse().GetErrorType();
  }
}
}
