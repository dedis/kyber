
#include <QtNetwork>

#include "DissentTest.hpp"
#include "TestWebClient.hpp"

namespace Dissent {
namespace Tests {

  void TestWebClient::Get(const QUrl url)
  {
    _reply = _qnam.get(QNetworkRequest(url));
    connect(_reply, SIGNAL(finished()), this, SLOT(HttpFinished()));
  }
  
  void TestWebClient::Post(const QUrl url, const QByteArray &body)
  {
    _reply = _qnam.post(QNetworkRequest(url), body);
    connect(_reply, SIGNAL(finished()), this, SLOT(HttpFinished()));
  }

  void TestWebClient::HttpFinished() 
  {
    EXPECT_TRUE(_expect_error == bool(_reply->error()));
    if(_reply->error()) {
      emit Error(_reply->error());
    } 
    QSharedPointer<QByteArray> data(new QByteArray(_reply->readAll()));
    emit Response(data);

    EXPECT_EQ(_output.count(), data->count());
    EXPECT_EQ(_output, *data);
    emit Done();
    _reply->deleteLater();
    _reply = 0;
  }

}
}
