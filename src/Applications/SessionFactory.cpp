#include "SessionFactory.hpp"

#include "../Anonymity/GroupGenerator.hpp"
#include "../Anonymity/FixedSizeGroupGenerator.hpp"
#include "../Anonymity/NullRound.hpp"
#include "../Anonymity/Session.hpp"
#include "../Anonymity/SecureSession.hpp"
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

  void SessionFactory::Create(Node *node, const QString &type)
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
    Group group = node->GenerateGroup();
    Session *session = new Session(group, node->bg.GetId(), group.GetId(0),
        Id::Zero, node->bg.GetConnectionTable(), node->bg.GetRpcHandler(),
        &NullRound::CreateRound, NullRound::DefaultData);
    Common(node, session);
  }

  void SessionFactory::CreateShuffleRoundSession(Node *node)
  {
    AsymmetricKey *key= CppPrivateKey::GenerateKey(node->bg.GetId().GetByteArray());
    node->key = QSharedPointer<AsymmetricKey>(key);

    Group group = node->GenerateGroup();
    Session *session = new SecureSession(group, node->bg.GetId(), group.GetId(0),
        Id::Zero, node->bg.GetConnectionTable(), node->bg.GetRpcHandler(),
        node->key, &ShuffleRound::CreateRound, ShuffleRound::DefaultData);
    Common(node, session);
  }

  void SessionFactory::CreateFastShuffleRoundSession(Node *node)
  {
    AsymmetricKey *key= CppPrivateKey::GenerateKey(node->bg.GetId().GetByteArray());
    node->key = QSharedPointer<AsymmetricKey>(key);

    Group group = node->GenerateGroup();
    Session *session = new SecureSession(group, node->bg.GetId(), group.GetId(0),
        Id::Zero, node->bg.GetConnectionTable(), node->bg.GetRpcHandler(),
        node->key, &ShuffleRound::CreateRound, ShuffleRound::DefaultData,
        &FixedSizeGroupGenerator::Create);
    Common(node, session);
  }

  void SessionFactory::Common(Node *node, Session *session)
  {
    node->session = QSharedPointer<Session>(session);
    node->sm.AddSession(node->session);

    QObject::connect(session, SIGNAL(RoundFinished(Session *, Round *)),
        node, SLOT(RoundFinished(Session *, Round *)));

    if(!node->sink.isNull()) {
      node->session->SetSink(node->sink.data());
    }
    node->session->Start();
  }
}
}
