#ifndef DISSENT_CONNECTIONS_NULL_CONNECTION_H_GUARD
#define DISSENT_CONNECTIONS_NULL_CONNECTION_H_GUARD

#include "Connection.hpp"
#include "../Transports/NullEdge.hpp"

namespace Dissent {
namespace Connections {
  /**
   * Useful for making null connections without an underlying edge
   */
  class NullConnection : public Connection {

    public:
      /**
       * Constructor
       * @param local_id the Id of the local member
       * @param remote_id the Id of the remote member
       */
      NullConnection(const Id &local_id, const Id &remote_id) :
        Connection(QSharedPointer<Edge>(new NullEdge()), local_id, remote_id) {}

      /**
       * Destructor
       */
      virtual ~NullConnection() {}

      inline virtual void Send(const QByteArray &data)
      {
        PushData(data, this);
      }
  };
}
}

#endif
