#ifndef DISSENT_APPLICATIONS_CONSOLE_SINK_H_GUARD
#define DISSENT_APPLICATIONS_CONSOLE_SINK_H_GUARD

#include <QTextStream>
#include "../Messaging/ISink.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Print async output to the stdout
   */
  class ConsoleSink : public Dissent::Messaging::ISink {
    public:
      typedef Dissent::Messaging::ISender ISender;

      explicit ConsoleSink();

      /**
       * Destructor
       */
      virtual ~ConsoleSink() {}

      virtual void HandleData(const QByteArray &data, ISender *from);

    protected:
      QTextStream _qtout;
  };
}
}

#endif
