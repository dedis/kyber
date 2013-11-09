#ifndef DISSENT_CONNECTIONS_IFORWARDER_H_GUARD
#define DISSENT_CONNECTIONS_IFORWARDER_H_GUARD

namespace Dissent {
namespace Connections {

  /**
   * Interface for a general purpose (overlay) message forwarder
   */
  class IForwarder {
    public:
      virtual ~IForwarder() {}

      /**
       * Send a message
       * @param to The remote destination
       * @param data The message payload
       */
      virtual void Forward(const Id &to, const QByteArray &data) = 0;
  };

}
}
#endif
