#ifndef DISSENT_ISENDER_H_GUARD
#define DISSENT_ISENDER_H_GUARD

#include <QByteArray>
#include <QDebug>
#include <QSharedPointer>
#include <QString>

namespace Dissent {
namespace Messaging {
  /**
   * Derivatives should implement a block-free Send
   */
  class ISender {
    public:
      /**
       * Send a message to a remote peer
       * @param data the message for the remote peer
       */
      virtual void Send(const QByteArray &data) = 0;

      /**
       * Presents the ISender in a string format
       */
      virtual QString ToString() const { return "Unknown ISender"; }

      /**
       * Virtual destructor
       */
      virtual ~ISender() {}
  };

  inline QDebug operator<<(QDebug dbg, ISender *sender)
  {
    dbg.nospace() << sender->ToString();
    return dbg.space();
  }

  inline QDebug operator<<(QDebug dbg, const QSharedPointer<ISender> &sender)
  {
    dbg.nospace() << sender->ToString();
    return dbg.space();
  }

  inline QDebug operator<<(QDebug dbg, const ISender &sender)
  {
    dbg.nospace() << sender.ToString();
    return dbg.space();
  }
}
}

#endif
