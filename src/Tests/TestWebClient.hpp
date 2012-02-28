
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QObject>
#include <QSharedPointer>
#include <QUrl>

namespace Dissent {
namespace Tests {

  class TestWebClient : public QObject {
    Q_OBJECT

    public:

      TestWebClient(bool expect_error, QByteArray& output) : 
          _output(output),
          _expect_error(expect_error)
      {
      }

      ~TestWebClient() {}
      void Get(const QUrl url);

      void Post(const QUrl url, const QByteArray &body);

    signals:

      void Done();

      void Response(QByteArray data);

      void Error(QNetworkReply::NetworkError error);

    private slots:

      void HttpFinished();

    private:
      QByteArray _output;
      bool _expect_error;
      QNetworkAccessManager _qnam;
      QSharedPointer<QNetworkReply> _reply;
      QUrl _url;
  };

}
}
