#include "Transports/Edge.hpp"

#include "Connection.hpp"
#include "ConnectionTable.hpp"
#include "NullConnection.hpp"

namespace Dissent {
namespace Connections {
  ConnectionTable::ConnectionTable(const Id &local_id)
  {
    if(local_id != Id::Zero()) {
      QSharedPointer<Connection> con(new NullConnection(local_id, local_id));
      con->SetSharedPointer(con);
      QSharedPointer<Edge> edge = con->GetEdge();
      AddEdge(edge);
      AddConnection(con);
    }
  }

  ConnectionTable::~ConnectionTable()
  {
  }

  void ConnectionTable::AddEdge(const QSharedPointer<Edge> &edge)
  {
    _edges[edge.data()] = edge;
  }

  bool ConnectionTable::RemoveEdge(const Edge *edge)
  {
    return _edges.remove(edge) != 0;
  }

  QSharedPointer<Connection> ConnectionTable::GetConnection(const Id &id) const
  {
    return _id_to_con.value(id);
  }

  QSharedPointer<Connection> ConnectionTable::GetConnection(
      const Edge *edge) const
  {
    return _edge_to_con.value(edge);
  }

  void ConnectionTable::AddConnection(const QSharedPointer<Connection> &con)
  {
    _cons[con.data()] = con;
    _id_to_con[con->GetRemoteId()] = con;
    _edge_to_con[con->GetEdge().data()] = con;
  }

  bool ConnectionTable::Disconnect(Connection *con)
  {
    const Id &id = con->GetRemoteId();
    QSharedPointer<Edge> edge = con->GetEdge();

    if(_id_to_con.contains(id) && _id_to_con[id]->GetEdge() == edge) {
      _id_to_con.remove(id);
      return true;
    } else {
      qWarning() << "Connection asked to be removed by Id but not found: " << con->ToString();
      return false;
    }
  }

  bool ConnectionTable::RemoveConnection(Connection *con)
  {
    Edge *edge = con->GetEdge().data();
    bool found = false;

    if(_edge_to_con.contains(edge)) {
      _edge_to_con.remove(edge);
      found = true;
    } else {
      qWarning() << "Connection asked to be removed by Edge but not found:" << con->ToString();
    }

    if(_cons.contains(con)) {
      found |= (_cons.remove(con) != 0);
    } else {
      qWarning() << "Connection could not be found:" << con->ToString();
    }

    return found;
  }

  void ConnectionTable::PrintConnectionTable()
  {
    qDebug() << "======= Connection Table =======";
    foreach(const QSharedPointer<Connection> &con, _cons) {
      qDebug() << con->ToString();
    }
    qDebug() << "================================";
  }
}
}
