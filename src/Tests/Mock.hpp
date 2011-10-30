#ifndef DISSENT_TESTS_MOCK_H_GUARD
#define DISSENT_TESTS_MOCK_H_GUARD

#include <QByteArray>
#include <QObject>
#include <QScopedPointer>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Transports;
  }

  class MockSource : public Source {
    public:
      void IncomingData(const QByteArray &data, ISender *from);
  };

  class MockSender : public ISender {
    public:
      MockSender(MockSource *source);
      virtual void Send(const QByteArray &data);
      void SetReturnPath(ISender *sender);
    private:
      MockSource *_source;
      ISender *_from;
  };

  class MockSink : public ISink {
    public:
      virtual ~MockSink() {}
      virtual void HandleData(const QByteArray &data, ISender *from);
      const QByteArray GetLastData();
      ISender *GetLastSender();
    private:
      ISender *_last_sender;
      QByteArray _last_data;
  };

  class MockSinkWithSignal : public QObject, public MockSink {
    Q_OBJECT

    public:
      virtual ~MockSinkWithSignal() {}
      virtual void HandleData(const QByteArray &data, ISender *from);
    signals:
      void ReadReady(MockSinkWithSignal *sink);
  };

  class MockEdgeHandler : public QObject {
    Q_OBJECT

    public:
      MockEdgeHandler(EdgeListener *el);
      QScopedPointer<Edge> edge;
    private slots:
      void HandleEdge(Edge *edge);
  };
  
  void MockExec();
}
}
#endif
