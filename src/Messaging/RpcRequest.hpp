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
  typedef QVariantHash RpcContainer;

  /**
   * Private data holder for RpcRequest
   */
  class RpcRequestData : public QSharedData {
    public:
      explicit RpcRequestData(const RpcContainer &message, ISender *from) :
        Message(message), From(from), Responded(false)
      {
      }

      virtual ~RpcRequestData() {}

      const RpcContainer Message;
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
       * Constructor, default construction NOT recommended!
       */
      explicit RpcRequest(const RpcContainer &message = RpcContainer(),
          ISender *from = 0);

      virtual ~RpcRequest() {}

      /**
       * Response to a request
       * @param response encoded response for the remote peer
       */
      virtual void Respond(RpcContainer response);

      /**
       * Was there a response sent yet?
       */
      inline virtual bool Responded() const { return _data->Responded; }

      /**
       * The message sent from the remote peer
       */
      inline const RpcContainer &GetMessage() const { return _data->Message; }

      /**
       * Pathway back to the remote peer
       */
      inline ISender *GetFrom() { return _data->From; }

      static const QString IdField;
      static const QString MethodField;
      static const QString NotificationType;
      static const QString RequestType;
      static const QString TypeField;
    private:
      QExplicitlySharedDataPointer<RpcRequestData> _data;
  };
}
}

#endif
