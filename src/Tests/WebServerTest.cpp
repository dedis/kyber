#include <QByteArray>
#include <QDebug>
#include <QEventLoop>
#include <QList>
#include <QSharedPointer>
#include <QUrl>

#include "DissentTest.hpp"

#include "TestWebClient.hpp"
#include "Dissent.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
    using namespace Dissent::Web::Services;
  }

  QSharedPointer<WebServer> StartServer(QUrl url) {
    QSharedPointer<WebServer> ws(new WebServer(url));

    QSharedPointer<GetMessagesService> get_messages_sp(new GetMessagesService()); 
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages", get_messages_sp);

    return ws;
  }

  TEST(WebServer, Normal)
  {
    QUrl url;
    url.setPort(50123);
    url.setHost("0.0.0.0");

    QSharedPointer<WebServer> ws = StartServer(url);
    ws->Start();

    QByteArray output = "{ \"output\" : { \"messages\" : [  ], \"offset\" : 0, \"total\" : 0 }, "
                          "\"api_version\" : \"0.0.0\", "
                          "\"copyright\" : \"2011 by Yale University\" }\n";
    TestWebClient wc(false, output);
  
    /* Create a loop that waits for the Done() signal */
    QEventLoop loop;
    QObject::connect(&wc, SIGNAL(Done()), &loop, SLOT(quit()));

    wc.Get(QUrl(QString("http://localhost:50123/session/messages?offset=0&count=-1")));

    /* Wait until HTTP request finishes */
    loop.exec();
  }

  TEST(WebServer, ManyRequests)
  {
    QUrl url;
    url.setPort(50123);
    url.setHost("0.0.0.0");

    QSharedPointer<WebServer> ws = StartServer(url);
    ws->Start();

    QByteArray output = "{ \"output\" : { \"messages\" : [  ], \"offset\" : 0, \"total\" : 0 }, "
                          "\"api_version\" : \"0.0.0\", "
                          "\"copyright\" : \"2011 by Yale University\" }\n";

    const int reqs = 100;

    for(int i=0; i<reqs; i++) {
      QEventLoop loop;
      TestWebClient wc(false, output);
      QObject::connect(&wc, SIGNAL(Done()), &loop, SLOT(quit()));
      wc.Get(QUrl(QString("http://localhost:50123/session/messages?offset=0&count=-1")));
      loop.exec();
    }

  }

  TEST(WebServer, Error404)
  {
    QUrl url;
    url.setPort(50123);
    url.setHost("0.0.0.0");

    QSharedPointer<WebServer> ws = StartServer(url);
    ws->Start();

    QByteArray output = "<html><body><h1>404: Not Found</h1></body></html>";
    TestWebClient wc(true, output);
  
    /* Create a loop that waits for the Done() signal */
    QEventLoop loop;
    QObject::connect(&wc, SIGNAL(Done()), &loop, SLOT(quit()));

    wc.Get(QUrl(QString("http://localhost:50123/session/id")));

    /* Wait until HTTP request finishes */
    loop.exec();
  }
}
}
