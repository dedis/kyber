#ifndef DISSENT_TESTS_TEST_RPC_H_GUARD
#define DISSENT_TESTS_TEST_RPC_H_GUARD

#include <QDebug>
#include <QObject>

#include "Dissent.hpp"

namespace Dissent {
namespace Tests {
  class TestRpc : public QObject {
    Q_OBJECT

    public slots:
      void Add(const Request &request)
      {
        QVariantList data = request.GetData().toList();

        bool ok;
        int x = data[0].toInt(&ok);
        if(!ok) {
          request.Failed(Response::InvalidInput, QString("Term 0 is invalid"));
          return;
        }

        int y = data[1].toInt(&ok);
        if(!ok) {
          request.Failed(Response::InvalidInput, QString("Term 1 is invalid"));
          return;
        }

        request.Respond(x + y);
      }
  };

  class TestResponse : public QObject {
    Q_OBJECT
    public:
      TestResponse() : _response(QSharedPointer<ISender>(), QVariantList())
      {
      }

      int GetValue() { return _response.GetData().toInt(); }
      Response GetResponse() { return _response; }

    public slots:
      void HandleResponse(const Response &response)
      {
        _response = response;
      }

    private:
      Response _response;
  };
}
}

#endif
