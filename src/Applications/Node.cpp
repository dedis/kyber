#include "Connections/Connection.hpp"
#include "Crypto/CryptoFactory.hpp"

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
    QObject::connect(&bg.GetConnectionManager(),
        SIGNAL(NewConnection(Connection *)),
        this, SLOT(HandleConnection(Connection *)));
  }

  Node::~Node()
  {
    QObject::disconnect(this, SIGNAL(Ready()), 0 ,0);
  }

  void Node::HandleConnection(Connection *con)
  {
    if(creds.GetLocalId() == base_group.GetLeader()) {
      CreateSession();
    }

    if(con->GetRemoteId() != base_group.GetLeader()) {
      return;
    }

    CreateSession();
  }

  void Node::CreateSession()
  {
    QObject::disconnect(&bg.GetConnectionManager(),
        SIGNAL(NewConnection(Connection *)),
        this, SLOT(HandleConnection(Connection *)));
    SessionFactory::GetInstance().Create(this, Id::Zero(),
        base_group, SessionType);
    emit Ready();
    QObject::disconnect(this, SIGNAL(Ready()), 0 ,0);
  }
}
}
