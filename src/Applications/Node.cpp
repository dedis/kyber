#include "Connections/Connection.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "Node.hpp"
#include "SessionFactory.hpp"


using Dissent::Identity::GroupContainer;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Library;
using Dissent::Crypto::CryptoFactory;

namespace Dissent {
namespace Applications {
  Node::Node(const Credentials &creds,
      const Group &group,
      const QList<Address> &local,
      const QList<Address> &remote,
      const QSharedPointer<ISink> &sink,
      const QString &type) :
    _creds(creds),
    _group(group),
    _overlay(new BasicGossip(creds.GetLocalId(), local, remote)),
    _net(new DefaultNetwork(_overlay->GetConnectionManager(),
          _overlay->GetRpcHandler())),
    _sm(_overlay->GetRpcHandler()),
    _sink(sink)
  {
    SessionFactory::GetInstance().Create(this, Id::Zero(), type);
  }

  Node::~Node()
  {
  }
}
}
