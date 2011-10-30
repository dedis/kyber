#ifndef DISSENT_APPLICATIONS_CONSOLE_SINK_H_GUARD
#define DISSENT_APPLICATIONS_CONSOLE_SINK_H_GUARD

#include <QTextStream>
#include "../Messaging/ISink.hpp"

namespace Dissent {
namespace Applications {
  namespace {
    using namespace Dissent::Messaging;
  }

  /**
   * Print async output to the stdout
   */
  class ConsoleSink : public ISink {
    public:
      ConsoleSink();
      virtual void HandleData(const QByteArray &data, ISender *from);

    protected:
      QTextStream _qtout;
  };
}
}

#endif
