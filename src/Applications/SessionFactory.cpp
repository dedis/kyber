#include "Anonymity/BulkRound.hpp"
#include "Anonymity/CSBulkRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/Session.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Anonymity/Tolerant/TolerantBulkRound.hpp"
#include "Anonymity/Tolerant/TolerantTreeRound.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/Id.hpp"
#include "Messaging/RpcHandler.hpp"

#include "SessionFactory.hpp"

using Dissent::Anonymity::BulkRound;
using Dissent::Anonymity::CSBulkRound;
using Dissent::Anonymity::NullRound;
using Dissent::Anonymity::RepeatingBulkRound;
using Dissent::Anonymity::Tolerant::TolerantBulkRound;
using Dissent::Anonymity::Tolerant::TolerantTreeRound;
using Dissent::Anonymity::Session;
using Dissent::Anonymity::ShuffleRound;
using Dissent::Anonymity::TCreateRound;
using Dissent::Connections::ConnectionManager;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Network;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Identity::Group;
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
    AddCreateCallback("csbulk", &CreateCSBulkRoundSession);
    AddCreateCallback("repeatingbulk", &CreateRepeatingBulkRoundSession);
    AddCreateCallback("tolerantbulk", &CreateTolerantBulkRoundSession);
    AddCreateCallback("toleranttree", &CreateTolerantTreeRoundSession);
  }

  void SessionFactory::AddCreateCallback(const QString &type, Callback cb)
  {
    _type_to_create[type] = cb;
  }

  void SessionFactory::Create(Node *node, const Id &session_id,
      const QString &type) const
  {
    Callback cb = _type_to_create[type];
    if(cb == 0) {
      qCritical() << "No known type: " << type;
      return;
    }
    cb(node, session_id);
  }

  void SessionFactory::CreateNullRoundSession(Node *node, const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<NullRound>);
  }

  void SessionFactory::CreateShuffleRoundSession(Node *node,
      const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<ShuffleRound>);
  }

  void SessionFactory::CreateBulkRoundSession(Node *node, const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<BulkRound>);
  }

  void SessionFactory::CreateCSBulkRoundSession(Node *node, const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<CSBulkRound>);
  }

  void SessionFactory::CreateRepeatingBulkRoundSession(Node *node,
      const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<RepeatingBulkRound>);
  }

  void SessionFactory::CreateTolerantBulkRoundSession(Node *node,
      const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<TolerantBulkRound>);
  }

  void SessionFactory::CreateTolerantTreeRoundSession(Node *node,
      const Id &session_id)
  {
    Common(node, session_id, &TCreateRound<TolerantTreeRound>);
  }

  void SessionFactory::Common(Node *node, const Id &session_id, CreateRound cr)
  {
    Session *session = new Session(node->GetGroupHolder(), node->GetPrivateIdentity(),
        session_id, node->GetNetwork(), cr);

    QObject::connect(node->GetOverlay().data(), SIGNAL(Disconnecting()),
        session, SLOT(CallStop()));

    QSharedPointer<Session> psession(session);
    session->SetSharedPointer(psession);
    node->GetSessionManager().AddSession(psession);

    psession->SetSink(node->GetSink().data());
    psession->Start();
  }
}
}
