#include <QList>

#include "Connections/Connection.hpp"
#include "Connections/RelayEdge.hpp"
#include "Messaging/Request.hpp"

#include "CSForwarder.hpp"

namespace Dissent {

using Connections::Connection;
using Connections::RelayEdge;

namespace ClientServer {
  CSForwarder::CSForwarder(const Id &local_id, const ConnectionTable &ct,
      const QSharedPointer<RpcHandler> &rpc,
      const QSharedPointer<GroupHolder> &group_holder) :
    RelayForwarder(local_id, ct, rpc),
    _group_holder(group_holder)
  {
  }

  CSForwarder::~CSForwarder()
  {
  }

  void CSForwarder::Forward(const Id &to, const QByteArray &data,
      const QStringList &been)
  {
    QHash<int, bool> tested;

    QSharedPointer<Connection> con = GetConnectionTable().GetConnection(to);

    if(!con || con->GetEdge().dynamicCast<Connections::RelayEdge>()) {
      const QList<QSharedPointer<Connection> > cons =
        GetConnectionTable().GetConnections();

      if(cons.size() == 0) {
        return;
      }

      Dissent::Utils::Random &rand = Dissent::Utils::Random::GetInstance();
      int idx = rand.GetInt(0, cons.size());
      con = cons[idx];
      tested[idx] = true;

      bool consider_group = _group_holder->GetGroup().Count() > 0;

      while(been.contains(con->GetRemoteId().ToString()) ||
          con->GetEdge().dynamicCast<Connections::RelayEdge>() ||
          (consider_group &&
           !_group_holder->GetGroup().GetSubgroup().Contains(con->GetRemoteId())))
      {
        if(tested.size() == cons.size()) {
          qWarning() << "Packet has been to all of our connections." <<
           "Destination:" << to.ToString();
          return;
        }

        idx = rand.GetInt(0, cons.size());
        con = cons[idx];
        tested[idx] = true;
      }
    }

    Send(con, to, data, been);
  }
}
}
