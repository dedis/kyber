#include "ConnectionTable.hpp"

namespace Dissent {
namespace Connections {
  ConnectionTable::~ConnectionTable()
  {
    foreach(Connection *con, _cons) {
      delete con;
    }
  }

  void ConnectionTable::AddEdge(Edge *edge)
  {
    if(edge->SafeToDelete()) {
      _edges[edge] = QSharedPointer<Edge>(edge);
    } else {
      _edges[edge] = QSharedPointer<Edge>(edge, &QObject::deleteLater);
    }
  }

  bool ConnectionTable::RemoveEdge(const Edge *edge)
  {
    return _edges.remove(edge) != 0;
  }

  Connection *ConnectionTable::GetConnection(const Id &id) const
  {
    if(_id_to_con.contains(id)) {
      return _id_to_con[id];
    }
    return 0;
  }

  Connection *ConnectionTable::GetConnection(const Edge *edge) const
  {
    if(_edge_to_con.contains(edge)) {
      return _edge_to_con[edge];
    }
    return 0;
  }

  void ConnectionTable::AddConnection(Connection *con)
  {
    _cons[con] = con;
    _id_to_con[con->GetRemoteId()] = con;
    _edge_to_con[con->GetEdge()] = con;
  }

  bool ConnectionTable::Disconnect(Connection *con)
  {
    const Id &id = con->GetRemoteId();
    Edge *edge = con->GetEdge();

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
    Edge *edge = con->GetEdge();
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
}
}
