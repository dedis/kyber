#include "SessionFactory.hpp"

#include "../Anonymity/GroupGenerator.hpp"
#include "../Anonymity/FixedSizeGroupGenerator.hpp"
#include "../Anonymity/NullRound.hpp"
#include "../Anonymity/Session.hpp"
#include "../Anonymity/ShuffleRound.hpp"

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
    Common(node, NullRound::Create, GroupGenerator::Create);
  }

  void SessionFactory::CreateShuffleRoundSession(Node *node)
  {
    Common(node, ShuffleRound::Create, GroupGenerator::Create);
  }

  void SessionFactory::CreateFastShuffleRoundSession(Node *node)
  {
    Common(node, ShuffleRound::Create, FixedSizeGroupGenerator::Create);
  }

  void SessionFactory::Common(Node *node, CreateRound cr, CreateGroupGenerator cgg)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    AsymmetricKey *key= lib->GeneratePrivateKey(node->bg.GetId().GetByteArray());
    node->key = QSharedPointer<AsymmetricKey>(key);

    Group group = node->GenerateGroup();
    Session *session = new Session(group, node->bg.GetId(), group.GetId(0),
        Id::Zero, node->bg.GetConnectionTable(), node->bg.GetRpcHandler(),
        cr, node->key, cgg);

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
