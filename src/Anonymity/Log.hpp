#ifndef DISSENT_ANONYMITY_LOG_H_GUARD
#define DISSENT_ANONYMITY_LOG_H_GUARD

#include <QByteArray>
#include <QVector>

#include "../Connections/Id.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using Dissent::Connections::Id;
  }

  /**
   * Maintains a historical mapping of a packet to an Id
   */
  class Log {
    public:
      /**
       * Default constructor
       */
      Log() { }

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
       * @param entry data in the log
       * @param remote Id in the log
       */
      bool At(int idx, QByteArray &entry, Id &remote);

      /**
       * Returns a serialized Log
       */
      QByteArray Serialize();

      /**
       * Returns the amount of entries in the log
       */
      inline int Count() { return _entries.count(); }

      /**
       * Clears the log
       */
      void Clear();

    private:
      QVector<QByteArray> _entries;
      QVector<Id> _remote;
  };
}
}

#endif
