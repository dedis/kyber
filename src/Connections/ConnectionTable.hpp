#ifndef DISSENT_CONNECTIONS_CONNECTION_TABLE_H_GUARD
#define DISSENT_CONNECTIONS_CONNECTION_TABLE_H_GUARD

#include <QDebug>
#include <QHash>

#include "Id.hpp"
#include "Connection.hpp"
#include "../Transports/Edge.hpp"

namespace Dissent {
namespace Connections {
  namespace {
    using namespace Dissent::Transports;
  }

  /**
   * Contains mappings for remote peers
   */
  class ConnectionTable {
    public:
      /**
       * Deconstructor
       */
      ~ConnectionTable();

      /**
       * Add an edge
       * @param edge the edge to add
       */
      void AddEdge(Edge *edge);

      /**
       * Remove an edge, returns true if it is stored
       * @param edge the edge to remvoe
       */
      bool RemoveEdge(const Edge *edge);

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
      Connection *GetConnection(const Id &id) const;

      /**
       * Returns a the connection matching to the edge or 0 if none exists
       * @param edge the edge to lookup
       */
      Connection *GetConnection(const Edge *edge) const;

      inline QList<Connection *> GetConnections() { return _cons.values(); }

      /**
       * Adds a Connection
       * @param con the connection to add
       */
      void AddConnection(Connection *con);

      /**
       * Removes the connection from being stored, returns true if exists.
       * Should only be called after the edge has been closed.
       * @param con the stored connection
       */
      bool RemoveConnection(Connection *con);

    private:
      /**
       * Stores Id to Connection mappings
       */
      QHash<const Id, Connection *> _id_to_con;

      /**
       * Stores Edge to Connection mappings
       */
      QHash<const Edge *, Connection *> _edge_to_con;

      /**
       * Stores Connections
       */
      QHash<const Connection *, Connection *> _cons;

      /**
       * Stores Edges
       */
      QHash<const Edge *, Edge *> _edges;
  };
}
}

#endif
