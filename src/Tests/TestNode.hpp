#ifndef DISSENT_TESTS_NULL_ROUND_TEST_H_GUARD
#define DISSENT_TESTS_NULL_ROUND_TEST_H_GUARD

#include "DissentTest.hpp"


namespace Dissent {
namespace Tests {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Transports;
    using namespace Dissent::Connections;
    using namespace Dissent::Anonymity;
  }

  class TestNode : public QObject {
    Q_OBJECT

    public:
      TestNode(int idx) : cm(Id(), &rpc), sm(&rpc)
      {
        BufferEdgeListener *be = new BufferEdgeListener(BufferAddress(idx));
        cm.AddEdgeListener(be);
      }

      ~TestNode()
      {
      }

      MockSink sink;
      RpcHandler rpc;
      ConnectionManager cm;
      SessionManager sm;
      Session *session;
      static int calledback;

    public slots:
      void HandleRoundFinished(Session *, Round *)
      {
        calledback++;
      }
  };

}
}

#endif
