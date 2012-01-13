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
      const QList<Address> &remote, const Group &group, const QString &type,
      const QSharedPointer<ISink> &sink) :
    creds(creds),
    bg(creds.GetLocalId(), local, remote),
    sm(bg.GetRpcHandler()),
    base_group(group),
    SessionType(type),
    sink(sink)
  {
  }

  void Node::StartSession()
  {
    SessionFactory::GetInstance().Create(this, Id::Zero(),
        base_group, SessionType);
  }

  Node::~Node()
  {
  }
}
}
