#ifndef DISSENT_RPC_REQUEST_H_GUARD
#define DISSENT_RPC_REQUEST_H_GUARD

#include <stdexcept>

#include <QDebug>
#include <QSharedData>
#include <QVariant>
#include <QtCore/qdatastream.h>

#include "ISender.hpp"

namespace Dissent {
namespace Messaging {
  /**
   * Private data holder for RpcRequest
   */
  class RpcRequestData : public QSharedData {
    public:
      RpcRequestData(const QVariantMap message, ISender *from) :
        Message(message), From(from), Responded(false)
      {
      }

      virtual ~RpcRequestData() {}

      const QVariantMap Message;
      ISender *From;
      bool Responded;

      RpcRequestData(const RpcRequestData &other) : QSharedData(other)
      {
        throw std::logic_error("Not callable");
      }
  
      RpcRequestData &operator=(const RpcRequestData &)
      {
        throw std::logic_error("Not callable");
      }
  };

  /**
   * Represents the state of an Rpc Request
   */
  class RpcRequest {
    public:
      /**
       * Constructor
       */
      RpcRequest(const QVariantMap &message = QVariantMap(), ISender *from = 0);

      virtual ~RpcRequest() {}

      /**
       * Response to a request
       * @param response encoded response for the remote peer
       */
      virtual void Respond(QVariantMap &response);

      /**
       * Was there a response sent yet?
       */
      inline virtual bool Responded() const { return _data->Responded; }

      /**
       * The message sent from the remote peer
       */
      inline const QVariantMap &GetMessage() const { return _data->Message; }

      /**
       * Pathway back to the remote peer
       */
      inline ISender *GetFrom() { return _data->From; }

    private:
      QExplicitlySharedDataPointer<RpcRequestData> _data;
  };
}
}

#endif
