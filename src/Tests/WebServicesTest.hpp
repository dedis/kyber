
#include <QList>
#include <QObject>
#include <QSharedPointer>

#include "DissentTest.hpp"
#include "Web/WebRequest.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
  }

  class WebServiceTestSink : public QObject {
    Q_OBJECT

    public slots:
      void HandleDoneRequest(QSharedPointer<WebRequest> wrp);

    public:
      QList<QSharedPointer<WebRequest> > handled;

  };

  /** 
   * Generate a Fake WebRequest
   */
  QSharedPointer<WebRequest> FakeRequest();

  /**
   * Run a test of a successful request on the web service when the
   * anonymity session is active
   * @param the web service
   * @param the length of the ID that this service returns
   */
  void SessionServiceActiveTestWrapper(QSharedPointer<WebService> wsp, int expected_id_len);

  /**
   * Run a test of a successful request on the web service when the
   * anonymity session is NOT active
   * @param the web service
   * @param the length of the ID that this service returns
   */
  void SessionServiceInactiveTestWrapper(QSharedPointer<WebService> wsp);
}
}
