#include "ClientServer/CSNetwork.hpp"
#include "ClientServer/CSOverlay.hpp"
#include "Connections/Connection.hpp"
#include "Connections/DefaultNetwork.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Overlay/BasicGossip.hpp"

#include "Node.hpp"
#include "SessionFactory.hpp"

using Dissent::Identity::GroupContainer;
using Dissent::ClientServer::CSNetwork;
using Dissent::ClientServer::CSOverlay;
using Dissent::Connections::DefaultNetwork;
using Dissent::Connections::Id;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::DiffieHellman;
using Dissent::Crypto::Library;
using Dissent::Crypto::CryptoFactory;
using Dissent::Overlay::BasicGossip;

namespace Dissent {
namespace Applications {
  Node::Node(const Credentials &creds,
      const QSharedPointer<GroupHolder> &group_holder,
      const QSharedPointer<BaseOverlay> &overlay,
      const QSharedPointer<Network> &network,
      const QSharedPointer<ISink> &sink,
      const QString &type) :
    _creds(creds),
    _group_holder(group_holder),
    _overlay(overlay),
    _net(network),
    _sm(_overlay->GetRpcHandler()),
    _sink(sink)
  {
    SessionFactory::GetInstance().Create(this, Id::Zero(), type);
  }

  Node::~Node()
  {
  }

  QSharedPointer<Node> Node::CreateBasicGossip(const Credentials &creds,
      const Group &group, const QList<Address> &local,
      const QList<Address> &remote, const QSharedPointer<ISink> &sink,
      const QString &session)
  {
    QSharedPointer<GroupHolder> gh(new GroupHolder(group));
    QSharedPointer<BaseOverlay> overlay(new BasicGossip(creds.GetLocalId(),
          local, remote));
    QSharedPointer<Network> network(new DefaultNetwork(
          overlay->GetConnectionManager(),
          overlay->GetRpcHandler()));
    return QSharedPointer<Node>(new Node(creds, gh, overlay,
          network, sink, session));
  }

  QSharedPointer<Node> Node::CreateClientServer(const Credentials &creds,
      const Group &group, const QList<Address> &local,
      const QList<Address> &remote, const QSharedPointer<ISink> &sink,
      const QString &session)
  {
    QSharedPointer<GroupHolder> gh(new GroupHolder(group));
    QSharedPointer<CSOverlay> overlay(new CSOverlay(creds.GetLocalId(),
          local, remote, group));
    QObject::connect(gh.data(), SIGNAL(GroupUpdated()),
        overlay.data(), SLOT(GroupUpdated()));
    QSharedPointer<Network> network(new CSNetwork(
          overlay->GetConnectionManager(),
          overlay->GetRpcHandler(),
          gh));
    return QSharedPointer<Node>(new Node(creds, gh, overlay,
          network, sink, session));
  }
}
}
