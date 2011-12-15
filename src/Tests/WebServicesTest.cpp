#include <QByteArray>
#include <QDebug>
#include <QList>
#include <QMap>
#include <QTextStream>
#include <QVariant>

#include "Web/WebRequest.hpp"
#include "Web/Services/GetMessagesService.hpp"
#include "Web/Services/GetNextMessageService.hpp"
#include "Web/Services/RoundIdService.hpp"
#include "Web/Services/SendMessageService.hpp"
#include "Web/Services/SessionIdService.hpp"

#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

#include "WebServicesTest.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
    using namespace Dissent::Web::Services;
  }

  void WebServiceTestSink::HandleDoneRequest(QSharedPointer<WebRequest> wrp)
  {
    handled.append(wrp);
  }

  QSharedPointer<WebRequest> FakeRequest()
  {
    QTcpSocket *socketp = new QTcpSocket();
    QSharedPointer<WebRequest> wrp(new WebRequest(socketp));

    QByteArray data = "POST /session/send HTTP/1.1\r\n\r\nHello!";
    wrp->GetRequest().ParseRequest(data);
    return wrp;
  }

  TEST(WebServices, GetMessagesService)
  {
    WebServiceTestSink sink;
    GetMessagesService gsm;
    QObject::connect(&gsm, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

    QByteArray data1, data2;
    data1 = "Test 1";
    data2 = "Test 2";

    ASSERT_EQ(sink.handled.count(), 0);

    gsm.Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());

    gsm.HandleIncomingMessage(data1);
    ASSERT_EQ(sink.handled.count(), 1);
    
    gsm.Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 2);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[1]->GetStatus());

    QVariant var = sink.handled[1]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::List));
    QList<QVariant> list = var.toList();
    ASSERT_TRUE(list[0].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, list[0].toByteArray());

    
    gsm.HandleIncomingMessage(data2);
    ASSERT_EQ(sink.handled.count(), 2);
    
    gsm.Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 3);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[2]->GetStatus());

    var = sink.handled[2]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::List));
    list = var.toList();
    ASSERT_TRUE(list[1].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, list[1].toByteArray());
  }

  TEST(WebServices, GetNextMessageService)
  {
    WebServiceTestSink sink;
    GetNextMessageService gnm;
    QObject::connect(&gnm, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

    QByteArray data1, data2;
    data1 = "Msg 1";
    data2 = "Msg 2";

    ASSERT_EQ(sink.handled.count(), 0);

    gnm.Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 0);

    gnm.HandleIncomingMessage(data1);
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());

    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Map));
    QMap<QString,QVariant> map = var.toMap();
    ASSERT_TRUE(map["message"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, map["message"].toByteArray());

    gnm.Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);

    gnm.HandleIncomingMessage(data2);
    ASSERT_EQ(sink.handled.count(), 2);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[1]->GetStatus());

    ASSERT_TRUE(var.canConvert(QVariant::Map));
    map = var.toMap();
    ASSERT_TRUE(map["message"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(data1, map["message"].toByteArray());
  }

  void SessionServiceActiveTestWrapper(QSharedPointer<WebService> wsp, int expected_id_len) 
  {
    WebServiceTestSink sink;
    ASSERT_EQ(sink.handled.count(), 0);

    QObject::connect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
   
    wsp->Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());
    
    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Map));
    QMap<QString,QVariant> map = var.toMap();
    ASSERT_TRUE(map["active"].canConvert(QVariant::Bool));
    ASSERT_TRUE(map["active"].toBool());
    ASSERT_TRUE(map["id"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(expected_id_len, map["id"].toByteArray().length());
    
    QObject::disconnect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
  }

  void SessionServiceInactiveTestWrapper(QSharedPointer<WebService> wsp) {
    WebServiceTestSink sink;
    ASSERT_EQ(sink.handled.count(), 0);

    QObject::connect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
   
    wsp->Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());
    
    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Map));
    QMap<QString,QVariant> map = var.toMap();
    ASSERT_TRUE(map["active"].canConvert(QVariant::Bool));
    ASSERT_FALSE(map["active"].toBool());
    ASSERT_TRUE(map["id"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(0, map["id"].toByteArray().length());
    
    QObject::disconnect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

  }

  void RoundIdServiceTest(SessionManager &sm)
  {
    ASSERT_TRUE(!sm.GetDefaultSession().isNull());
    QSharedPointer<RoundIdService> ridp(new RoundIdService(sm));
    SessionServiceActiveTestWrapper(ridp, 4);
  }

  TEST(WebServices, RoundIdServiceActive)
  {
    RoundTest_Basic_SessionTest(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup, &RoundIdServiceTest);
  }

  TEST(WebServices, RoundIdServiceInactive)
  {
    SessionManager sm;
    QSharedPointer<RoundIdService> ridp(new RoundIdService(sm));
    SessionServiceInactiveTestWrapper(ridp);
  }

  void SessionIdServiceTest(SessionManager &sm)
  {
    ASSERT_TRUE(!sm.GetDefaultSession().isNull());
    QSharedPointer<SessionIdService> sisp(new SessionIdService(sm));
    SessionServiceActiveTestWrapper(sisp, 28);
  }

  TEST(WebServices, SessionIdServiceActive)
  {
    RoundTest_Basic_SessionTest(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup, &SessionIdServiceTest);
  }

  TEST(WebServices, SessionIdServiceInactive)
  {
    SessionManager sm;
    QSharedPointer<SessionIdService> sisp(new SessionIdService(sm));
    SessionServiceInactiveTestWrapper(sisp);
  }

  void SendMessageServiceTest(SessionManager &sm)
  {
    ASSERT_TRUE(!sm.GetDefaultSession().isNull());
    QSharedPointer<SendMessageService> smsp(new SendMessageService(sm));
    SessionServiceActiveTestWrapper(smsp, 28);
  }

  TEST(WebServices, SendMessageServiceActive)
  {
    RoundTest_Basic_SessionTest(&TCreateSession<ShuffleRound>,
        Group::CompleteGroup, &SendMessageServiceTest);
  }

  TEST(WebServices, SendMessageServiceInactive)
  {
    SessionManager sm;
    QSharedPointer<SendMessageService> smsp(new SendMessageService(sm));
    SessionServiceInactiveTestWrapper(smsp);
  }
}
}
