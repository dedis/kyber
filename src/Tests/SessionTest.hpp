#ifndef DISSENT_TEST_SESSION_TEST_H_GUARD
#define DISSENT_TEST_SESSION_TEST_H_GUARD

#include "DissentTest.hpp"
#include "OverlayTest.hpp"

namespace Dissent {
namespace Tests {
  typedef QSharedPointer<ServerSession> ServerPointer;
  typedef QSharedPointer<ClientSession> ClientPointer;

  class Sessions {
    public:
      OverlayNetwork network;
      QList<ServerPointer> servers;
      QList<ClientPointer> clients;
      QHash<QString, QSharedPointer<AsymmetricKey> > private_keys;
      QSharedPointer<KeyShare> keys;
      QList<QSharedPointer<BufferSink> > sinks;
      QList<QSharedPointer<SignalSink> > signal_sinks;
      QList<QSharedPointer<SinkMultiplexer> > sink_multiplexers;
      CreateRound create_round;
  };

  Sessions BuildSessions(const OverlayNetwork &network,
      CreateRound create_round = TCreateRound<NullRound>);
  void StartSessions(const Sessions &sessions);
  void StartRound(const Sessions &sessions);
  void CompleteRound(const Sessions &sessions);
  void StopSessions(const Sessions &sessions);
  void SendTest(const Sessions &sessions);
  void DisconnectServer(Sessions &sessions, bool hard);
}
}

#endif
