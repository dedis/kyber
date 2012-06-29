#ifndef DISSENT_CONNECTIONS_IOVERLAY_SENDER_H_GUARD
#define DISSENT_CONNECTIONS_IOVERLAY_SENDER_H_GUARD

#include "Messaging/ISender.hpp"

#include "Id.hpp"

namespace Dissent {
namespace Connections {
  /**
   * An interface which allows a sender or similar object share overlay
   * source and destination information.
   */
  class IOverlaySender : public Messaging::ISender {
    public:
      /**
       * Returns the local id
       */
      virtual Id GetLocalId() const = 0;

      /**
       * Returns the remote id
       */
      virtual Id GetRemoteId() const = 0;

      inline static Id GetRemoteId(const QSharedPointer<ISender> &sender)
      {
        return GetRemoteId(sender.data());
      }

      inline static Id GetRemoteId(const ISender *sender)
      {
        const IOverlaySender *ov_sender = dynamic_cast<const IOverlaySender *>(sender);
        if(ov_sender) {
          return ov_sender->GetRemoteId();
        } else {
          return Id::Zero();
        }
      }
  };
}
}

#endif
