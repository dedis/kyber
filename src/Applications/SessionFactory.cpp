#include "../Anonymity/GroupGenerator.hpp"
#include "../Anonymity/FixedSizeGroupGenerator.hpp"
#include "../Anonymity/NullRound.hpp"
#include "../Anonymity/Session.hpp"
#include "../Anonymity/ShuffleRound.hpp"
#include "../Anonymity/Round.hpp"
#include "../Connections/ConnectionTable.hpp"
#include "../Connections/DefaultNetwork.hpp"
#include "../Connections/Id.hpp"
#include "../Messaging/RpcHandler.hpp"

#include "SessionFactory.hpp"

using Dissent::Anonymity::FixedSizeGroupGenerator;
using Dissent::Anonymity::Group;
using Dissent::Anonymity::GroupGenerator;
using Dissent::Anonymity::NullRound;
using Dissent::Anonymity::Session;
using Dissent::Anonymity::ShuffleRound;
using Dissent::Anonymity::TCreateRound;
using Dissent::Connections::ConnectionTable;
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
    AddCreateCallback("fastshuffle", &CreateFastShuffleRoundSession);
  }

  void SessionFactory::AddCreateCallback(const QString &type, Callback cb)
  {
    _type_to_create[type] = cb;
  }

  void SessionFactory::Create(Node *node, const QString &type) const
  {
    Callback cb = _type_to_create[type];
    if(cb == 0) {
      qCritical() << "No known type: " << type;
      return;
    }
    cb(node);
  }

  void SessionFactory::CreateNullRoundSession(Node *node)
  {
    Common(node, &TCreateRound<NullRound>, GroupGenerator::Create);
  }

  void SessionFactory::CreateShuffleRoundSession(Node *node)
  {
    Common(node, &TCreateRound<ShuffleRound>, GroupGenerator::Create);
  }

  void SessionFactory::CreateFastShuffleRoundSession(Node *node)
  {
    Common(node, &TCreateRound<ShuffleRound>, FixedSizeGroupGenerator::Create);
  }

  void SessionFactory::Common(Node *node, CreateRound cr, CreateGroupGenerator cgg)
  {
    Group group = node->GenerateGroup();
    const ConnectionTable &ct = node->bg.GetConnectionTable();
    RpcHandler &rpc = node->bg.GetRpcHandler();
    QSharedPointer<Network> net(new DefaultNetwork(ct, rpc));

    Session *session = new Session(group, node->creds, group.GetId(0),
        Id::Zero(), net, cr, cgg);

    node->session = QSharedPointer<Session>(session);
    node->sm.AddSession(node->session);

    QObject::connect(session, SIGNAL(RoundFinished(QSharedPointer<Round>)),
        node, SLOT(RoundFinished(QSharedPointer<Round>)));

    if(!node->sink.isNull()) {
      node->session->SetSink(node->sink.data());
    }
    node->session->Start();
  }
}
}
