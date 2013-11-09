#ifndef DISSENT_APPLICATIONS_FILE_SINK_H_GUARD
#define DISSENT_APPLICATIONS_FILE_SINK_H_GUARD

#include <QFile>
#include <QTextStream>

#include "Messaging/ISinkObject.hpp"

namespace Dissent {
namespace Applications {
  /**
   * Print async output to the stdout
   */
  class FileSink : public Messaging::ISinkObject {
    public:
      typedef Messaging::ISender ISender;

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

      virtual void HandleData(const QSharedPointer<ISender> &from,
          const QByteArray &data);

    private:
      QFile m_file;
      QTextStream m_out;
      bool m_valid;
  };
}
}

#endif
