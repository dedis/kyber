#ifndef DISSENT_APPLICATIONS_FILE_SINK_H_GUARD
#define DISSENT_APPLICATIONS_FILE_SINK_H_GUARD

#include <QFile>
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
  class FileSink : public ISink {
    public:
      /**
       * Constructor
       * @param file the file to store the output into
       */
      FileSink(const QString &file);

      /**
       * Destructor
       */
      virtual ~FileSink() {}

      /**
       * Was the file properly opened
       */
      bool IsValid();

      virtual void HandleData(const QByteArray &data, ISender *from);

    private:
      QFile _file;
      QTextStream _out;
      bool _valid;
  };
}
}

#endif
