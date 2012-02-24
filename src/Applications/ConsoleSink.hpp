#ifndef DISSENT_APPLICATIONS_CONSOLE_SINK_H_GUARD
#define DISSENT_APPLICATIONS_CONSOLE_SINK_H_GUARD

#include <QTextStream>
#include "Messaging/ISinkObject.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Print async output to the stdout
   */
  class ConsoleSink : public Messaging::ISinkObject {
    public:
      typedef Messaging::ISender ISender;

      explicit ConsoleSink();

      /**
       * Destructor
       */
      virtual ~ConsoleSink() {}

      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data);

    protected:
      QTextStream _qtout;
  };
}
}

#endif
