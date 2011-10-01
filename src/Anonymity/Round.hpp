#ifndef DISSENT_ANONYMITY_ROUND_H_GUARD
#define DISSENT_ANONYMITY_ROUND_H_GUARD

#include <stdexcept>

#include <QObject>

#include "../Connections/ConnectionTable.hpp"
#include "../Messaging/ISender.hpp"
#include "../Messaging/Source.hpp"
#include "../Messaging/RpcHandler.hpp"

#include "Group.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Connections;
  }

  /**
   * Represents a single instance of a cryptographically secure anonymous exchange
   */
  class Round : public QObject, public Source, public ISender, public ISink {
    Q_OBJECT

    public:
      Round(const Id &local_id, const Group &group, ConnectionTable &ct,
          RpcHandler *rpc, const Id &round_id);

      virtual void Start() = 0;
      virtual void HandleData(const QByteArray &data, ISender *from);
      virtual QString ToString();

      void Close();
      void Close(const QString &reason);

      inline const QString &GetClosedReason() { return _closed_reason; }
      inline bool Closed() { return _closed; }
      inline const Id &GetId() { return _round_id; }

      /**
       * Send is not implemented, it is here simply so we can reuse the Source
       * paradigm and have the session recognize which round produced the result
       */
      virtual void Send(const QByteArray &data);

    signals:
      void Finished(Round *round);

    protected:
      void Broadcast(const QByteArray &data);
      void Send(const QByteArray &data, const Id &id);
      const Id _local_id;
      const Group _group;

    private:
      virtual void ProcessData(const QByteArray &data, const Id &id) = 0;
      QString _closed_reason;
      const ConnectionTable &_ct;
      RpcHandler *_rpc;
      const Id _round_id;
      bool _closed;

    private slots:
      virtual void HandleDisconnect(Connection *con, const QString &reason);
  };
}
}

#endif
