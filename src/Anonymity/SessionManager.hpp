#ifndef DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD
#define DISSENT_ANONYMITY_SESSION_MANAGER_H_GUARD

#include "../Messaging/RpcHandler.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Messaging;
  }

  class SessionManager : public QObject, public Filter {
    Q_OBJECT

    public:
      SessionManager(RpcHandler *rpc);
      ~SessionManager();
      void AddRound(Round *round);
      virtual void Send(const QByteArray &data);

    private:
      void IncomingData(RpcRequest &notification);
      QHash<Id, Round *> _id_to_round;
      RpcMethod<SessionManager> _data;
      RpcHandler *_rpc;
  };
}
}

#endif
