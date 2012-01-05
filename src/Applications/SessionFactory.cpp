#include "Anonymity/BulkRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/Session.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Anonymity/TrustedBulkRound.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/Id.hpp"
#include "Messaging/RpcHandler.hpp"

#include "SessionFactory.hpp"

using Dissent::Anonymity::BulkRound;
using Dissent::Anonymity::Group;
using Dissent::Anonymity::NullRound;
using Dissent::Anonymity::RepeatingBulkRound;
using Dissent::Anonymity::Session;
using Dissent::Anonymity::ShuffleRound;
using Dissent::Anonymity::TCreateRound;
using Dissent::Anonymity::TrustedBulkRound;
using Dissent::Connections::ConnectionManager;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Network;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Messaging::RpcHandler;

namespace Dissent {
namespace Applications {
  SessionFactory &SessionFactory::GetInstance()
  {
    static SessionFactory sf;
    return sf;
  }

  SessionFactory::SessionFactory()
  {
    AddCreateCallback("null", &CreateNullRoundSession);
    AddCreateCallback("shuffle", &CreateShuffleRoundSession);
    AddCreateCallback("bulk", &CreateBulkRoundSession);
    AddCreateCallback("repeatingbulk", &CreateRepeatingBulkRoundSession);
    AddCreateCallback("trustedbulk", &CreateTrustedBulkRoundSession);
  }

  void SessionFactory::AddCreateCallback(const QString &type, Callback cb)
  {
    _type_to_create[type] = cb;
  }

  void SessionFactory::Create(Node *node, const Id &session_id, const Group &group,
      const QString &type) const
  {
    Callback cb = _type_to_create[type];
    if(cb == 0) {
      qCritical() << "No known type: " << type;
      return;
    }
    cb(node, session_id, group);
  }

  void SessionFactory::CreateNullRoundSession(Node *node, const Id &session_id,
      const Group &group)
  {
    Common(node, session_id, &TCreateRound<NullRound>, group);
  }

  void SessionFactory::CreateShuffleRoundSession(Node *node,
      const Id &session_id, const Group &group)
  {
    Common(node, session_id, &TCreateRound<ShuffleRound>, group);
  }

  void SessionFactory::CreateBulkRoundSession(Node *node, const Id &session_id,
      const Group &group)
  {
    Common(node, session_id, &TCreateRound<BulkRound>, group);
  }

  void SessionFactory::CreateRepeatingBulkRoundSession(Node *node,
      const Id &session_id, const Group &group)
  {
    Common(node, session_id, &TCreateRound<RepeatingBulkRound>, group);
  }

  void SessionFactory::CreateTrustedBulkRoundSession(Node *node,
      const Id &session_id, const Group &group)
  {
    Common(node, session_id, &TCreateRound<TrustedBulkRound>, group);
  }

  void SessionFactory::Common(Node *node, const Id &session_id, CreateRound cr,
      const Group &group)
  {
    ConnectionManager &cm = node->bg.GetConnectionManager();
    RpcHandler &rpc = node->bg.GetRpcHandler();
    QSharedPointer<Network> net(new DefaultNetwork(cm, rpc));

    Session *session = new Session(group, node->creds, session_id, net, cr);
    QSharedPointer<Session> psession(session);

    node->sm.AddSession(psession);

    if(!node->sink.isNull()) {
      psession->SetSink(node->sink.data());
    }
    psession->Start();
  }
}
}
