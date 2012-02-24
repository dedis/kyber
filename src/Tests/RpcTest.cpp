#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Rpc, HelloWorld)
  {
    QSharedPointer<RpcHandler> rpc0(new RpcHandler());
    QSharedPointer<MockSource> ms0(new MockSource());;
    ms0->SetSink(rpc0);
    QSharedPointer<MockSender> to_ms0(new MockSender(ms0));

    QSharedPointer<RpcHandler> rpc1(new RpcHandler());
    QSharedPointer<MockSource> ms1(new MockSource());;
    ms1->SetSink(rpc1);
    QSharedPointer<MockSender> to_ms1(new MockSender(ms1));
    to_ms0->SetReturnPath(to_ms1);
    to_ms1->SetReturnPath(to_ms0);

    TestRpc test0;
    QSharedPointer<RequestHandler> req_h(new RequestHandler());
    QObject::connect(req_h.data(), SIGNAL(MakeRequestSignal(const Request &)),
        &test0, SLOT(Add(const Request &)));
    rpc0->Register("add", req_h);

    QVariantList data;
    data.append(3);
    data.append(6);

    TestResponse test1;
    QSharedPointer<ResponseHandler> res_h(new ResponseHandler());
    QObject::connect(res_h.data(),
        SIGNAL(RequestCompleteSignal(const Response &)),
        &test1, SLOT(HandleResponse(const Response &)));

    EXPECT_EQ(0, test1.GetValue());
    rpc1->SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(9, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());

    data[1] = "Haha";
    rpc1->SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());

    data[0] = "Haha";
    rpc1->SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());

    data[0] = 8;
    data[1] = 2;
    rpc1->SendRequest(to_ms0, "add", data, res_h);
    EXPECT_EQ(10, test1.GetValue());
    EXPECT_TRUE(test1.GetResponse().Successful());

    rpc1->SendRequest(to_ms0, "Haha", data, res_h);
    EXPECT_EQ(0, test1.GetValue());
    EXPECT_FALSE(test1.GetResponse().Successful());
  }
}
}
