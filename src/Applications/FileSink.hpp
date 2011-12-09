#ifndef DISSENT_APPLICATIONS_FILE_SINK_H_GUARD
#define DISSENT_APPLICATIONS_FILE_SINK_H_GUARD

#include <QFile>
#include <QTextStream>

#include "../Messaging/ISink.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Print async output to the stdout
   */
  class FileSink : public Dissent::Messaging::ISink {
    public:
      typedef Dissent::Messaging::ISender ISender;

      /**
       * Constructor
       * @param file the file to store the output into
       */
      explicit FileSink(const QString &file);

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
