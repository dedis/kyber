#ifndef DISSENT_CONNECTIONS_CONNECTION_TABLE_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_TABLE_H_GUARD

#include <QDebug>
#include <QHash>
#include <QSharedPointer>

#include "Id.hpp"

namespace Dissent {
namespace Transports {
  class Edge;
}

namespace Connections {
  class Connection;

  /**
   * Contains mappings for remote peers
   */
  class ConnectionTable {
    public:
      typedef Transports::Edge Edge;

      /**
       * Constructor
       * @param local_id so we have a "connection" to ourself
       */
      explicit ConnectionTable(const Id &local_id = Id::Zero());

      /**
       * Deconstructor
       */
      ~ConnectionTable();

      /**
       * Add an edge
       * @param edge the edge to add
       */
      void AddEdge(const QSharedPointer<Edge> &edge);

      /**
       * Remove an edge, returns true if it is stored
       * @param edge the edge to remvoe
       */
      bool RemoveEdge(const Edge *edge);

      /**
       * Returns true if the connection is in the table
       */
      inline bool Contains(const Connection *con)
      {
        return _cons.contains(con);
      }

      /**
       * Remove a connection from being looked up by Id or Edge, returns
       * true if exists.  Should be called after calling disconnect but
       * before an edge is closed.
       * @param con the connection to remove
       */
      bool Disconnect(Connection *con);

      /**
       * Returns the connection matching to the Id or 0 if none exists
       * @param id the Id to lookup
       */
      QSharedPointer<Connection> GetConnection(const Id &id) const;

      /**
       * Returns a the connection matching to the edge or 0 if none exists
       * @param edge the edge to lookup
       */
      QSharedPointer<Connection> GetConnection(const Edge *edge) const;

      inline const QList<QSharedPointer<Connection> > GetConnections() const
      {
        return _cons.values();
      }

      inline const QList<QSharedPointer<Edge> > GetEdges() const
      {
        return _edges.values();
      }

      /**
       * Adds a Connection
       * @param con the connection to add
       */
      void AddConnection(const QSharedPointer<Connection> &con);

      /**
       * Removes the connection from being stored, returns true if exists.
       * Should only be called after the edge has been closed.
       * @param con the stored connection
       */
      bool RemoveConnection(Connection *con);

      /**
       * Print connection table to debug output
       */
      void PrintConnectionTable();

    private:
      /**
       * Stores Id to Connection mappings
       */
      QHash<const Id, QSharedPointer<Connection> > _id_to_con;

      /**
       * Stores Edge to Connection mappings
       */
      QHash<const Edge *, QSharedPointer<Connection> > _edge_to_con;

      /**
       * Stores Connections
       */
      QHash<const Connection *, QSharedPointer<Connection> > _cons;

      /**
       * Stores Edges
       */
      QHash<const Edge *, QSharedPointer<Edge> > _edges;
  };
}
}

#endif
