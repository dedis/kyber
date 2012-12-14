#include <QByteArray>
#include <QDebug>
#include <QUrl>

#include "DissentTest.hpp"
#include "Web/HttpRequest.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
  }

  TEST(HttpRequest, ParseBadRequests)
  {
    QByteArray bytes;
    
    bytes = "";
    HttpRequest req0;
    ASSERT_FALSE(req0.ParseRequest(bytes));

    bytes = "Junk";
    HttpRequest req1;
    ASSERT_FALSE(req1.ParseRequest(bytes));

    bytes = "\r\n\r\nJunk";
    HttpRequest req2;
    ASSERT_FALSE(req2.ParseRequest(bytes));

    bytes = "HTTP/1.1 GET /stuff\r\n";
    HttpRequest req3;
    ASSERT_FALSE(req3.ParseRequest(bytes));

    bytes = "HTTP/1.1 GET /stuff\r\n\r\nBody\r\n";
    HttpRequest req4;
    ASSERT_FALSE(req4.ParseRequest(bytes));

//    While the version number is bad ... this looks like a valid request...
//    bytes = "GET /stuff HTTP/3.0\r\n\r\n\r\n";
//    HttpRequest req5;
//    ASSERT_FALSE(req5.ParseRequest(bytes));

    bytes = "DELETE @#@)(#$*/stuff HTTP/3.0\r\n\r\n\r\n";
    HttpRequest req6;
    ASSERT_FALSE(req6.ParseRequest(bytes));

    bytes = "MAKE_SANDWICH / HTTP/1.1\r\n\r\n\r\n";
    HttpRequest req7;
    ASSERT_FALSE(req7.ParseRequest(bytes));
   
    bytes = "GET / HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    HttpRequest req8;
    ASSERT_TRUE(req8.ParseRequest(bytes));
  }

  TEST(HttpRequest, ParseGoodRequests)
  {
    QByteArray bytes;

    bytes = "GET /stuff.html HTTP/1.1\r\n\r\n";
    HttpRequest req0;
    ASSERT_TRUE(req0.ParseRequest(bytes));
    ASSERT_EQ(req0.GetMethod(), HttpRequest::METHOD_HTTP_GET);
    ASSERT_EQ(QUrl("/stuff.html"), req0.GetUrl());
    ASSERT_EQ(QUrl("/stuff.html"), req0.GetPath());
    ASSERT_EQ(QString(""), req0.GetBody());

    bytes = "GET /stuff.html HTTP/1.1\r\n\r\n";
    HttpRequest req1;
    ASSERT_TRUE(req1.ParseRequest(bytes));
    ASSERT_EQ(req1.GetMethod(), HttpRequest::METHOD_HTTP_GET);
    ASSERT_EQ(QUrl("/stuff.html"), req1.GetUrl());
    ASSERT_EQ(QUrl("/stuff.html"), req1.GetPath());
    ASSERT_EQ(QString(""), req1.GetBody());

    bytes = "GET /stuff.html?params HTTP/1.1\r\n\r\n\r\n";
    HttpRequest req2;
    ASSERT_TRUE(req2.ParseRequest(bytes));
    ASSERT_EQ(QUrl("/stuff.html"), req2.GetPath());
    ASSERT_EQ(req2.GetMethod(), HttpRequest::METHOD_HTTP_GET);
    ASSERT_EQ(QUrl("/stuff.html?params"), req2.GetUrl());
    ASSERT_EQ(QString(""), req2.GetBody());
    
    bytes = "POST /messages/send.php HTTP/1.1\r\nContent-Length: 4\r\n\r\nBody\r\n";
    HttpRequest req3;
    ASSERT_TRUE(req3.ParseRequest(bytes));
    ASSERT_EQ(req3.GetMethod(), HttpRequest::METHOD_HTTP_POST);
    ASSERT_EQ(QUrl("/messages/send.php"), req3.GetUrl());
    ASSERT_EQ(QUrl("/messages/send.php"), req3.GetPath());
    ASSERT_EQ(QString("Body"), req3.GetBody());
  }

}
}
