#ifndef DISSENT_ANONYMITY_LOG_H_GUARD
#define DISSENT_ANONYMITY_LOG_H_GUARD

#include <QByteArray>
#include <QPair>
#include <QVector>

namespace Dissent {
namespace Connections {
  class Id;
}

namespace Anonymity {
  /**
   * Maintains a historical mapping of a packet to an Id
   */
  class Log {
    public:
      typedef Dissent::Connections::Id Id;

      /**
       * Default constructor
       */
      Log();

      /**
       * Construct using a serialized log
       * @param logdata serialized log
       */
      Log(const QByteArray &logdata);

      /**
       * Adds a new message to the end of the log
       * @param entry the data to append
       * @param remote the remote entity (Id)
       */
      void Append(const QByteArray &entry, const Id &remote);

      /**
       * The last message added was bad, remove it
       */
      void Pop();

      /**
       * Returns the log entry at the specified index, true if it returns
       * valid data, false otherwise
       * @param idx index
       */
      const QPair<QByteArray, Id> &At(int idx) const;

      /**
       * Returns a serialized Log
       */
      QByteArray Serialize() const;

      /**
       * Returns the amount of entries in the log
       */
      inline int Count() { return _entries.count(); }

      /**
       * Clears the log
       */
      void Clear();

      /**
       * Disables logging
       */
      bool ToggleEnabled();

      /**
       * Returns if logging is enabled
       */
      inline bool Enabled() { return _enabled; }
    private:
      QVector<QPair<QByteArray, Id> > _entries;
      bool _enabled;
      static const QPair<QByteArray, Id> _empty;
  };
}
}

#endif
