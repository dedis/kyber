#include "Anonymity/BaseBulkRound.hpp"
#include "Anonymity/BlogDropRound.hpp"
#include "Anonymity/BulkRound.hpp"
#include "Anonymity/CSBulkRound.hpp"
#include "Anonymity/RepeatingBulkRound.hpp"
#include "Anonymity/NeffKeyShuffleRound.hpp"
#include "Anonymity/NeffShuffleRound.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/Sessions/Session.hpp"
#include "Anonymity/Sessions/SessionLeader.hpp"
#include "Anonymity/ShuffleRound.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Connections/Id.hpp"
#include "Crypto/BlogDrop/Parameters.hpp"
#include "Identity/Authentication/NullAuthenticate.hpp"
#include "Identity/Authentication/NullAuthenticator.hpp"
#include "Messaging/RpcHandler.hpp"

#include "SessionFactory.hpp"
#include "Node.hpp"

using namespace Dissent::Anonymity;
using namespace Dissent::Anonymity::Sessions;
using Dissent::Connections::ConnectionManager;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Network;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::BlogDrop::Parameters;
using Dissent::Identity::Group;
using Dissent::Identity::Authentication::IAuthenticate;
using Dissent::Identity::Authentication::IAuthenticator;
using Dissent::Identity::Authentication::NullAuthenticate;
using Dissent::Identity::Authentication::NullAuthenticator;
using Dissent::Messaging::RpcHandler;

namespace Dissent {
namespace Applications {

  void SessionFactory::CreateSession(Node *node, const Id &session_id,
      SessionType type, AuthFactory::AuthType auth_type,
      const QSharedPointer<KeyShare> &public_keys)
  {
    CreateRound cr;
    switch(type) {
      case NULL_ROUND:
        cr = &TCreateRound<NullRound>;
        break;
      case SHUFFLE:
        cr = &TCreateRound<ShuffleRound>;
        break;
      case BULK:
        cr = &TCreateRound<BulkRound>;
        break;
      case REPEATING_BULK:
        cr = &TCreateRound<RepeatingBulkRound>;
        break;
      case CSBULK:
        cr = &TCreateBulkRound<CSBulkRound, NeffKeyShuffleRound>;
        break;
      case NEFF_SHUFFLE:
        cr = &TCreateRound<NeffShuffleRound>;
      case BLOG_DROP_REACTIVE:
        cr = TCreateBlogDropRound<Parameters::ParameterType_CppECHashingProduction,
           NeffShuffleRound>;
        break;
      case BLOG_DROP_PROACTIVE:
        cr = TCreateBlogDropRound<Parameters::ParameterType_CppECHashingProduction,
           NeffShuffleRound>;
        break;
      default:
        qFatal("Invalid session type");
    }

    QSharedPointer<IAuthenticate> authe(AuthFactory::CreateAuthenticate(
          node, auth_type, public_keys));

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
      QSharedPointer<IAuthenticator> autho(AuthFactory::CreateAuthenticator(
            node, auth_type, public_keys));
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
