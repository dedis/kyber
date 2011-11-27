#include "SessionFactory.hpp"

#include "../Anonymity/GroupGenerator.hpp"
#include "../Anonymity/FixedSizeGroupGenerator.hpp"
#include "../Anonymity/NullRound.hpp"
#include "../Anonymity/Session.hpp"
#include "../Anonymity/ShuffleRound.hpp"
#include "../Anonymity/Round.hpp"
#include "../Connections/DefaultNetwork.hpp"

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
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    AsymmetricKey *key= lib->GeneratePrivateKey(node->bg.GetId().GetByteArray());
    node->key = QSharedPointer<AsymmetricKey>(key);

    Group group = node->GenerateGroup();
    const ConnectionTable &ct = node->bg.GetConnectionTable();
    RpcHandler &rpc = node->bg.GetRpcHandler();
    QSharedPointer<Network> net(new DefaultNetwork(ct, rpc));

    Session *session = new Session(group, node->bg.GetId(), group.GetId(0),
        Id::Zero(), net, cr, node->key, cgg);

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
