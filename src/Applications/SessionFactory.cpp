#include "Anonymity/BaseBulkRound.hpp"
#include "Anonymity/BulkRound.hpp"
#include "Anonymity/CSBulkRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/NeffKeyShuffle.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionLeader.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Anonymity/Tolerant/TolerantBulkRound.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/Id.hpp"
#include "Identity/Authentication/NullAuthenticate.hpp"
#include "Identity/Authentication/NullAuthenticator.hpp"
#include "Messaging/RpcHandler.hpp"

#include "SessionFactory.hpp"

using Dissent::Anonymity::BulkRound;
using Dissent::Anonymity::CSBulkRound;
using Dissent::Anonymity::NeffKeyShuffle;
using Dissent::Anonymity::NullRound;
using Dissent::Anonymity::RepeatingBulkRound;
using Dissent::Anonymity::Tolerant::TolerantBulkRound;
using Dissent::Anonymity::Sessions::Session;
using Dissent::Anonymity::Sessions::SessionLeader;
using Dissent::Anonymity::ShuffleRound;
using Dissent::Anonymity::TCreateBulkRound;
using Dissent::Anonymity::TCreateRound;
using Dissent::Connections::ConnectionManager;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Network;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Library;
using Dissent::Identity::Group;
using Dissent::Identity::Authentication::IAuthenticate;
using Dissent::Identity::Authentication::IAuthenticator;
using Dissent::Identity::Authentication::NullAuthenticate;
using Dissent::Identity::Authentication::NullAuthenticator;
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
    Common(node, session_id, &TCreateBulkRound<CSBulkRound, NeffKeyShuffle>);
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

  void SessionFactory::Common(Node *node, const Id &session_id, CreateRound cr)
  {
    QSharedPointer<IAuthenticate> authe(
        new NullAuthenticate(node->GetPrivateIdentity()));

    Session *session = new Session(node->GetGroupHolder(), authe, session_id,
        node->GetNetwork(), cr);

    QObject::connect(node->GetOverlay().data(), SIGNAL(Disconnecting()),
        session, SLOT(CallStop()));

    QSharedPointer<Session> psession(session);
    session->SetSharedPointer(psession);
    node->GetSessionManager().AddSession(psession);

    psession->SetSink(node->GetSink().data());
    if(node->GetPrivateIdentity().GetLocalId() ==
        node->GetGroupHolder()->GetGroup().GetLeader())
    {
      QSharedPointer<IAuthenticator> autho(new NullAuthenticator());
      QSharedPointer<SessionLeader> sl(new SessionLeader(
            node->GetGroupHolder()->GetGroup(), node->GetPrivateIdentity(),
            node->GetNetwork(), psession, autho));
      node->GetSessionManager().AddSessionLeader(sl);
      sl->Start();
    } else {
      psession->Start();
    }
  }
}
}
