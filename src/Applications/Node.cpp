#include "Node.hpp"
#include "SessionFactory.hpp"
#include "../Crypto/CppPrivateKey.hpp"

namespace Dissent {
namespace Applications {
  Node::Node(const QList<Address> &local, const QList<Address> &remote,
      int group_size, const QString &session_type) :
    bg(local, remote),
    sm(bg.GetRpcHandler()),
    GroupSize(group_size),
    SessionType(session_type),
    _bootstrapped(false)
  {
    QObject::connect(&bg, SIGNAL(NewConnection(Connection *, bool)),
        this, SLOT(HandleConnection(Connection *, bool)));
  }

  void Node::HandleConnection(Connection *, bool local)
  {
    if(!local) {
      return;
    }

    QList<Connection *> cons = bg.GetConnectionTable().GetConnections();
    if(cons.count() != GroupSize - 1) {
      return;
    }

    QObject::disconnect(&bg, SIGNAL(NewConnection(Connection *, bool)),
        this, SLOT(HandleConnection(Connection *, bool)));
    SessionFactory::GetInstance().Create(this, SessionType);
    _bootstrapped = true;
    emit Ready(this);
  }

  void Node::RoundFinished(Session *, Round *)
  {
  }

  Group Node::GenerateGroup()
  {
    QVector<Id> ids;
    QVector<AsymmetricKey *> public_keys;

    foreach(Connection *con, bg.GetConnectionTable().GetConnections()) {
      Id id = con->GetRemoteId();
      ids.append(id);
    }

    ids.append(bg.GetId());

    qSort(ids);
    foreach(const Id &id, ids) {
      public_keys.append(CppPublicKey::GenerateKey(id.GetByteArray()));
    }

    return Group(ids, public_keys);
  }
}
}
