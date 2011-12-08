#include <QByteArray>
#include <QDebug>
#include <QString>
#include <QTextStream>

#include "DissentTest.hpp"
#include "Web/HttpResponse.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
  }

  TEST(HttpResponse, Normal)
  {
    QString output;
    QTextStream os(&output);
    
    HttpResponse resp;
    resp.SetStatusCode(HttpResponse::STATUS_OK);
    ASSERT_FALSE(resp.HasHeader("X-MyHeader"));
    resp.AddHeader("X-MyHeader","123");
    ASSERT_TRUE(resp.HasHeader("X-MyHeader"));

    resp.body << "Hello!\n";

    resp.WriteToStream(os);

    ASSERT_EQ("HTTP/1.1 200 OK\r\nX-MyHeader: 123\r\nContent-Length: 7\r\n\r\nHello!\n", output);
  }

  TEST(HttpResponse, NormalNoBody)
  {
    QString output;
    QTextStream os(&output);
    
    HttpResponse resp;
    resp.SetStatusCode(HttpResponse::STATUS_OK);
    ASSERT_FALSE(resp.HasHeader("X-MyHeader"));
    resp.AddHeader("X-MyHeader","123");
    ASSERT_TRUE(resp.HasHeader("X-MyHeader"));

    resp.WriteToStream(os);

    ASSERT_EQ("HTTP/1.1 200 OK\r\nX-MyHeader: 123\r\nContent-Length: 0\r\n\r\n", output);
  }

  TEST(HttpResponse, Error404NoBody)
  {
    QString output;
    QTextStream os(&output);
    
    HttpResponse resp;
    resp.SetStatusCode(HttpResponse::STATUS_NOT_FOUND);
    ASSERT_FALSE(resp.HasHeader("X-MyHeader"));
    resp.AddHeader("X-MyHeader","123");
    ASSERT_TRUE(resp.HasHeader("X-MyHeader"));

    resp.WriteToStream(os);

    QString error_body = "<html><body><h1>404: Not Found</h1></body></html>";

    ASSERT_EQ(QString("HTTP/1.1 404 Not Found\r\n"
              "X-MyHeader: 123\r\n"
              "Content-Length: %1\r\n\r\n").arg(error_body.length()) 
        + error_body, output);
  }

  TEST(HttpResponse, Error404)
  {
    QString output;
    QTextStream os(&output);
    
    HttpResponse resp;
    resp.SetStatusCode(HttpResponse::STATUS_NOT_FOUND);
    ASSERT_FALSE(resp.HasHeader("X-MyHeader"));
    resp.AddHeader("X-MyHeader","123");
    ASSERT_TRUE(resp.HasHeader("X-MyHeader"));

    resp.body << "Oh no!";

    resp.WriteToStream(os);

    QString error_body = "Oh no!";

    ASSERT_EQ(QString("HTTP/1.1 404 Not Found\r\n"
              "X-MyHeader: 123\r\n"
              "Content-Length: %1\r\n\r\n").arg(error_body.length()) 
        + error_body, output);
  }
}
}
