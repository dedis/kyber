#ifndef DISSENT_TRANSPORTS_EDGE_H_GUARD
#define DISSENT_TRANSPORTS_EDGE_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Messaging/ISender.hpp"
#include "Messaging/SourceObject.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/Time.hpp"

#include "Address.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Stores the state for a transport layer link between two peers
   */
  class Edge : public Messaging::SourceObject, public Messaging::ISender,
      public Utils::StartStop
  {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param local the local address of the edge
       * @param remote the address of the remote point of the edge
       * @param outbound true if the local side requested the creation of this edge
       */
      explicit Edge(const Address &local, const Address &remote, bool outbound);

      /**
       * Deconstructor
       */
      virtual ~Edge();

      /**
       * Returns a string representation of the edge
       */
      virtual QString ToString() const;

      /**
       * Returns the local address for the edge
       */
      inline const Address &GetLocalAddress() const { return _local_address; }

      /**
       * Returns the remote address for the edge
       */
      inline const Address &GetRemoteAddress() const { return _remote_address; }

      /**
       * Returns what is suspected to be the persistent remote address
       */
      inline const Address &GetRemotePersistentAddress() const
      {
        return _remote_p_addr;
      }

      /**
       * The remote address is the one the edge is actually using, the
       * persistent address is the one the remote side will use for new
       * connections
       * @param addr the remote peers persistent address
       */
      inline void SetRemotePersistentAddress(const Address &addr)
      {
        _remote_p_addr = addr;
      }

      /**
       * True if the local side requested creation of this edge
       */
      inline bool Outbound() const { return _outbound; }

      QSharedPointer<Edge> GetSharedPointer() { return _edge.toStrongRef(); }

      void SetSharedPointer(const QSharedPointer<Edge> &edge)
      {
        _edge = edge.toWeakRef();
      }

      /**
       * Gets the time for the last incoming packet
       */
      virtual qint64 GetLastIncomingMessage() const { return _last_incoming; }

    signals:
      void StoppedSignal();

    protected:
      /**
       * Overloaded to set the time the last message came in
       */
      inline virtual void PushData(const QSharedPointer<ISender> &from,
          const QByteArray &data)
      {
        _last_incoming = Utils::Time::GetInstance().MSecsSinceEpoch();
        SourceObject::PushData(from, data);
      }

      /**
       * Returns true if the object isn't fully closed
       */
      virtual bool RequiresCleanup() { return false; }

      /**
       * When the object is fully closed call this function
       */
      virtual void StopCompleted();

      /**
       * Called as a result of Stop has been called
       */
      virtual void OnStop();

    private:
      QWeakPointer<Edge> _edge;
      const Address _local_address;
      const Address _remote_address;
      Address _remote_p_addr;
      bool _outbound;
      qint64 _last_incoming;
  };
}
}
#endif
