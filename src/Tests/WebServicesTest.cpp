#include <QByteArray>
#include <QDebug>
#include <QList>
#include <QTextStream>
#include <QVariant>

#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "ShuffleRoundHelpers.hpp"

#include "WebServicesTest.hpp"

namespace Dissent {
namespace Tests {

  void WebServiceTestSink::HandleDoneRequest(QSharedPointer<WebRequest> wrp)
  {
    handled.append(wrp);
  }

  QSharedPointer<WebRequest> FakeRequest(const QString &url)
  {
    QTcpSocket *socketp = new QTcpSocket();
    QSharedPointer<WebRequest> wrp(new WebRequest(socketp));

    QByteArray data = QString("POST " + url + " HTTP/1.1\r\n\r\nHello!").toUtf8();
    wrp->GetRequest().ParseRequest(data);
    return wrp;
  }

  TEST(WebServices, GetMessagesService)
  {
    WebServiceTestSink sink;
    GetMessagesService gsm;
    QObject::connect(&gsm, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

    QByteArray data1, data2;
    data1 = "Test 1";
    data2 = "Test 2";

    ASSERT_EQ(sink.handled.count(), 0);
    QString request = "/some/path?offset=0&count=-1";

    gsm.Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());

    gsm.HandleIncomingMessage(data1);
    ASSERT_EQ(sink.handled.count(), 1);
    
    gsm.Call(FakeRequest(request));
    ASSERT_EQ(sink.handled.count(), 2);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[1]->GetStatus());

    QVariantHash hash = sink.handled[1]->GetOutputData().toHash();
    ASSERT_EQ(hash.count(), 3);
    QList<QVariant> list = hash["messages"].toList();
    ASSERT_EQ(list.count(), 1);
    ASSERT_EQ(data1, list[0].toByteArray());
    
    gsm.HandleIncomingMessage(data2);
    ASSERT_EQ(sink.handled.count(), 2);
    
    gsm.Call(FakeRequest(request));
    ASSERT_EQ(sink.handled.count(), 3);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[2]->GetStatus());

    hash = sink.handled[2]->GetOutputData().toHash();
    ASSERT_EQ(hash.count(), 3);
    list = hash["messages"].toList();
    ASSERT_EQ(list.count(), 2);
    ASSERT_EQ(data1, list[0].toByteArray());
    ASSERT_EQ(data2, list[1].toByteArray());

    request = "/some/path?offset=1&count=1";

    gsm.Call(FakeRequest(request));
    ASSERT_EQ(sink.handled.count(), 4);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[3]->GetStatus());

    hash = sink.handled[3]->GetOutputData().toHash();
    ASSERT_EQ(hash.count(), 3);
    list = hash["messages"].toList();
    ASSERT_EQ(list.count(), 1);
    ASSERT_EQ(data2, list[0].toByteArray());
  }

  TEST(WebServices, GetNextMessageService)
  {
    WebServiceTestSink sink;
    GetMessagesService gnm;
    QObject::connect(&gnm, SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));

    QByteArray data1, data2;
    data1 = "Msg 1";
    data2 = "Msg 2";

    ASSERT_EQ(sink.handled.count(), 0);

    gnm.Call(FakeRequest("/some/path?offset=0&count=1&wait=true"));
    ASSERT_EQ(sink.handled.count(), 0);

    gnm.HandleIncomingMessage(data1);
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());

    QVariantHash hash = sink.handled[0]->GetOutputData().toHash();
    ASSERT_EQ(hash.count(), 3);
    QList<QVariant> list = hash["messages"].toList();
    ASSERT_EQ(list.count(), 1);
    ASSERT_EQ(data1, list[0].toByteArray());

    gnm.Call(FakeRequest("/some/path?offset=1&count=1&wait=true"));
    ASSERT_EQ(sink.handled.count(), 1);

    gnm.HandleIncomingMessage(data2);
    ASSERT_EQ(sink.handled.count(), 2);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[1]->GetStatus());

    hash = sink.handled[1]->GetOutputData().toHash();
    ASSERT_EQ(hash.count(), 3);
    list = hash["messages"].toList();
    ASSERT_EQ(list.count(), 1);
    ASSERT_EQ(data2, list[0].toByteArray());
  }

  void SessionServiceActiveTestWrapper(QSharedPointer<WebService> wsp, int expected_id_len) 
  {
    WebServiceTestSink sink;
    ASSERT_EQ(sink.handled.count(), 0);

    QObject::connect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
   
    wsp->Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());
    
    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Hash));
    QVariantHash hash = var.toHash();
    ASSERT_TRUE(hash["active"].canConvert(QVariant::Bool));
    ASSERT_TRUE(hash["active"].toBool());
    ASSERT_TRUE(hash["id"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(expected_id_len, hash["id"].toByteArray().length());
    
    QObject::disconnect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
  }

  void SessionServiceInactiveTestWrapper(QSharedPointer<WebService> wsp) {
    WebServiceTestSink sink;
    ASSERT_EQ(sink.handled.count(), 0);

    QObject::connect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
       &sink, SLOT(HandleDoneRequest(QSharedPointer<WebRequest>)));
   
    wsp->Call(FakeRequest());
    ASSERT_EQ(sink.handled.count(), 1);
    ASSERT_EQ(HttpResponse::STATUS_OK, sink.handled[0]->GetStatus());
    
    QVariant var = sink.handled[0]->GetOutputData();
    ASSERT_TRUE(var.canConvert(QVariant::Hash));
    QVariantHash hash = var.toHash();
    ASSERT_TRUE(hash["active"].canConvert(QVariant::Bool));
    ASSERT_FALSE(hash["active"].toBool());
    ASSERT_TRUE(hash["id"].canConvert(QVariant::ByteArray));
    ASSERT_EQ(0, hash["id"].toByteArray().length());
    
    QObject::disconnect(wsp.data(), SIGNAL(FinishedWebRequest(QSharedPointer<WebRequest>, bool)),
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
