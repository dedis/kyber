#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "TestNode.hpp"
#include "Mock.hpp"

#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkAccessManager>

namespace Dissent {
namespace Tests {
  TEST(Web, NotFound)
  {
  }

  TEST(Web, Echo)
  {
    WebServer webserver(QUrl("tcp://127.0.0.1:" + QString::number(TEST_PORT)));
    QSharedPointer<EchoService> echo(new EchoService());
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_GET, "/echo", echo));
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_POST, "/echo", echo));
    webserver.Start();

    QNetworkAccessManager manager;
    QNetworkRequest request;
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    QString message("HELLO");
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/echo?" + message);

    QScopedPointer<QNetworkReply> reply(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    ASSERT_EQ(QString(reply->readAll()), message);

    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/echo");
    reply.reset(manager.post(request, message.toUtf8()));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    ASSERT_EQ(QString(reply->readAll()), message);

    webserver.Stop();
  }

  TEST(Web, File)
  {
    QString filename(QString::number(Random::GetInstance().GetInt()));
    while(QDir::temp().exists(filename)) {
      filename = QString::number(Random::GetInstance().GetInt());
    }

    QString filepath = QDir::tempPath() + "/" + filename;
    QFile file(filepath);

    CryptoRandom rand;
    QByteArray data(1000, 0);
    rand.GenerateBlock(data);
    ASSERT_TRUE(file.open(QIODevice::WriteOnly));
    ASSERT_EQ(file.write(data), data.size());
    file.close();

    WebServer webserver(QUrl("tcp://127.0.0.1:" + QString::number(TEST_PORT)));
    QSharedPointer<GetFileService> fileserv(new GetFileService(filepath));
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_GET, "/file", fileserv));
    webserver.Start();

    QNetworkAccessManager manager;
    QNetworkRequest request;
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/file");

    QScopedPointer<QNetworkReply> reply(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    QByteArray response = reply->readAll();
    ASSERT_EQ(response.size(), data.size());
    ASSERT_EQ(response, data);

    webserver.Stop();

    ASSERT_TRUE(file.remove());
  }

  TEST(Web, Directory)
  {
    QString dirname(QString::number(Random::GetInstance().GetInt()));
    while(QDir::temp().exists(dirname)) {
      dirname = QString::number(Random::GetInstance().GetInt());
    }
    
    QDir::temp().mkdir(dirname);
    QString dirpath = QDir::tempPath() + "/" + dirname;

    CryptoRandom rand;
    QByteArray data(1000, 0);

    QList<QString> files;
    for(int i = 0; i < 5; i++) {
      files.append(QString::number(Random::GetInstance().GetInt()));
      QString filepath = dirpath + "/" + files.last();
      QFile file(filepath);
      rand.GenerateBlock(data);
      ASSERT_TRUE(file.open(QIODevice::WriteOnly));
      ASSERT_EQ(file.write(data), data.size());
      file.close();
    }

    WebServer webserver(QUrl("tcp://127.0.0.1:" + QString::number(TEST_PORT)));
    QSharedPointer<GetDirectoryService> dirserv(new GetDirectoryService(dirpath));
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_GET, "/dir", dirserv));
    webserver.Start();

    QNetworkAccessManager manager;
    QNetworkRequest request;
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    foreach(const QString &filename, files) {
      request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/dir?file=" + filename);
      QScopedPointer<QNetworkReply> reply(manager.get(request));
      WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
      ASSERT_TRUE(reply->isFinished());
      QByteArray response = reply->readAll();

      QFile file(dirpath + "/" + filename);
      file.open(QIODevice::ReadOnly);
      QByteArray data = file.readAll();

      ASSERT_EQ(response.size(), data.size());
      ASSERT_EQ(response, data);
      file.remove();
    }

    webserver.Stop();

    ASSERT_TRUE(QDir::temp().rmdir(dirname));
  }

  TEST(Web, GetMessages)
  {
    WebServer webserver(QUrl("tcp://127.0.0.1:" + QString::number(TEST_PORT)));
    QSharedPointer<GetMessagesService> get_messages(new GetMessagesService()); 
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_GET, "/get", get_messages));
    webserver.Start();

    QNetworkAccessManager manager;
    QNetworkRequest request;
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");

    // nothing yet
    QString request_base = "http://127.0.0.1:" + QString::number(TEST_PORT) + "/get";
    request.setUrl(request_base);

    QScopedPointer<QNetworkReply> reply(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());

    QVariant result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    QVariantHash data = result.toHash();
    ASSERT_EQ(data["total"].toInt(), 0);
    ASSERT_EQ(data["offset"].toInt(), 0);
    ASSERT_TRUE(data["messages"].toList().isEmpty());

    // preparing some messages
    QByteArray data1 = "Test 1";
    QByteArray data1_t = QByteArray(8, 0) + data1;
    Utils::Serialization::WriteInt(data1.size(), data1_t, 0);
    QByteArray data2 = "Test 2";
    QByteArray data2_t = QByteArray(8, 0) + data1;
    Utils::Serialization::WriteInt(data1.size(), data1_t, 0);
    data2_t = QByteArray(8, 0) + data2;
    Utils::Serialization::WriteInt(data2.size(), data2_t, 0);

    // first message
    get_messages->HandleIncomingMessage(data1_t);
    request.setUrl(request_base + "?offset=0&count=-1");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_EQ(data["total"].toInt(), 1);
    ASSERT_EQ(data["offset"].toInt(), 0);
    ASSERT_EQ(data["messages"].toList().size(), 1);
    ASSERT_EQ(data["messages"].toList()[0].toByteArray(), data1);

    // second message
    get_messages->HandleIncomingMessage(data2_t);
    request.setUrl(request_base + "?offset=1&count=-1");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_EQ(data["total"], 2);
    ASSERT_EQ(data["offset"], 1);
    ASSERT_EQ(data["messages"].toList().size(), 1);
    ASSERT_EQ(data["messages"].toList()[0].toByteArray(), data2);

    // both
    request.setUrl(request_base + "?offset=0&count=-1");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_EQ(data["total"], 2);
    ASSERT_EQ(data["offset"], 0);
    ASSERT_EQ(data["messages"].toList().size(), 2);
    ASSERT_EQ(data["messages"].toList()[0].toByteArray(), data1);
    ASSERT_EQ(data["messages"].toList()[1].toByteArray(), data2);

    // Now wait!
    request.setUrl(request_base + "?offset=2&count=-1&wait=true");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_FALSE(reply->isFinished());
    
    // Now try again!
    get_messages->HandleIncomingMessage(data2_t);
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());

    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_EQ(data["total"], 3);
    ASSERT_EQ(data["offset"], 2);
    ASSERT_EQ(data["messages"].toList().size(), 1);
    ASSERT_EQ(data["messages"].toList()[0].toByteArray(), data2);

    webserver.Stop();
  }

/*  void RoundTest_Basic_SessionTest(SessionCreator callback,
      Group::SubgroupPolicy sg_policy, SessionTestCallback session_cb)
      */
  TEST(Web, Session)
  {
    CryptoRandom rand;
    QByteArray raw(750, 0);

    rand.GenerateBlock(raw);
    QByteArray message0 = ToUrlSafeBase64(raw);

    rand.GenerateBlock(raw);
    QByteArray message1 = ToUrlSafeBase64(raw);

    rand.GenerateBlock(raw);
    QByteArray message2 = ToUrlSafeBase64(raw);

    ConnectionManager::UseTimer = false;
    Timer::GetInstance().UseVirtualTime();

    int count = Random::GetInstance().GetInt(TEST_RANGE_MIN, TEST_RANGE_MAX);
//    int sender = Random::GetInstance().GetInt(0, count);

    QVector<TestNode *> nodes;
    Group group;
    ConstructOverlay(count, nodes, group, Group::ManagedSubgroup);

    // Build web server
    SignalCounter messages;
    SignalSink sink;
    WebServer webserver(QUrl("tcp://127.0.0.1:" + QString::number(TEST_PORT)));
    QSharedPointer<GetMessagesService> get_messages(new GetMessagesService()); 
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_GET, "/get", get_messages));
    QObject::connect(&sink, SIGNAL(IncomingData(const QByteArray&)),
        get_messages.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
    QObject::connect(&sink, SIGNAL(IncomingData(const QByteArray &)),
        &messages, SLOT(Counter()));

    SessionManager &sm = nodes[0]->sm;
    QSharedPointer<SendMessageService> send_message(new SendMessageService(sm));
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_POST, "/send", send_message));
    QSharedPointer<SessionService> session_service(new SessionService(sm));
    ASSERT_TRUE(webserver.AddRoute(QHttpRequest::HTTP_GET, "/session", session_service));
    webserver.Start();

    // Verify no session
    QNetworkAccessManager manager;
    QNetworkRequest request;
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/session");
    QScopedPointer<QNetworkReply> reply(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    QVariant result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    QVariantHash data = result.toHash();
    ASSERT_FALSE(data["session"].toBool());
    ASSERT_EQ(data["session_id"].toString(), "");
    ASSERT_FALSE(data["round"].toBool());
    ASSERT_EQ(data["round_id"].toString(), "");

    // Send before a session
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/send");
    reply.reset(manager.post(request, message0));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<bool>());
    ASSERT_FALSE(result.toBool());

    // Verify sessions / no round
    CreateSessions(nodes, group, Id(), SessionCreator(TCreateBulkRound<CSBulkRound, NeffKeyShuffleRound>));

    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/session");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_TRUE(data["session"].toBool());
    ASSERT_NE(data["session_id"].toString(), "");
    ASSERT_FALSE(data["round"].toBool());
    ASSERT_EQ(data["round_id"].toString(), "");

    // Set correct sink
    sm.GetDefaultSession()->SetSink(&sink);

    SignalCounter ready;
    for(int idx = 0; idx < count; idx++) {
      QObject::connect(nodes.last()->session.data(),
          SIGNAL(RoundStarting(const QSharedPointer<Round> &)),
          &ready, SLOT(Counter()));

      nodes[idx]->session->Start();
    }

    RunUntil(ready, count);

    // Send a message before a round
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/send");
    reply.reset(manager.post(request, message1));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<bool>());
    ASSERT_TRUE(result.toBool());

    // Verify session / round
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/session");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_TRUE(data["session"].toBool());
    ASSERT_NE(data["session_id"].toString(), "");
    ASSERT_TRUE(data["round"].toBool());
    ASSERT_NE(data["round_id"].toString(), "");

    RunUntil(messages, 1);
    ASSERT_EQ(nodes[0]->sink.Count(), 0);

    // Verify message
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/get?count=-1&offset=0");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());

    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_EQ(data["total"].toInt(), 1);
    ASSERT_EQ(data["offset"].toInt(), 0);
    ASSERT_EQ(data["messages"].toList().size(), 1);
    ASSERT_EQ(data["messages"].toList()[0], message1);

    // Send a message during a round
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/send");
    reply.reset(manager.post(request, message2));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());
    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<bool>());
    ASSERT_TRUE(result.toBool());

    RunUntil(messages, 2);

    // Verify message
    request.setUrl("http://127.0.0.1:" + QString::number(TEST_PORT) + "/get?count=-1&offset=0");
    reply.reset(manager.get(request));
    WaitCallback<QNetworkReply>(reply.data(), &QNetworkReply::isFinished);
    ASSERT_TRUE(reply->isFinished());

    result = QtJson::Json::parse(reply->readAll());
    ASSERT_TRUE(result.canConvert<QVariantHash>());
    data = result.toHash();
    ASSERT_EQ(data["total"].toInt(), 2);
    ASSERT_EQ(data["offset"].toInt(), 0);
    ASSERT_EQ(data["messages"].toList().size(), 2);
    ASSERT_EQ(data["messages"].toList()[0], message1);
    ASSERT_EQ(data["messages"].toList()[1], message2);

    CleanUp(nodes);
    ConnectionManager::UseTimer = true;
    webserver.Stop();
  }
}
}
