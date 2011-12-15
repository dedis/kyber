#include "../Connections/Connection.hpp"
#include "../Crypto/CryptoFactory.hpp"

#include "Node.hpp"
#include "SessionFactory.hpp"


using Dissent::Anonymity::GroupContainer;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Library;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace Applications {
  Node::Node(const Credentials &creds, const QList<Address> &local,
      const QList<Address> &remote, const Group &group, const QString &type) :
    creds(creds),
    bg(creds.GetLocalId(), local, remote),
    sm(bg.GetRpcHandler()),
    base_group(group),
    SessionType(type)
  {
    QObject::connect(&bg, SIGNAL(NewConnection(Connection *, bool)),
        this, SLOT(HandleConnection(Connection *, bool)));
  }

  Node::~Node()
  {
    QObject::disconnect(this, SIGNAL(Ready()), 0 ,0);
  }

  void Node::HandleConnection(Connection *con, bool local)
  {
    if(creds.GetLocalId() == base_group.GetLeader()) {
      CreateSession();
    }

    if(!local) {
      return;
    }

    if(con->GetRemoteId() != base_group.GetLeader()) {
      return;
    }

    CreateSession();
  }

  void Node::CreateSession()
  {
    QObject::disconnect(&bg, SIGNAL(NewConnection(Connection *, bool)),
        this, SLOT(HandleConnection(Connection *, bool)));
    SessionFactory::GetInstance().Create(this, Id::Zero(),
        base_group, SessionType);
    emit Ready();
    QObject::disconnect(this, SIGNAL(Ready()), 0 ,0);
  }
}
}
