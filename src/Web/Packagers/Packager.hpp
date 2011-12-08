#ifndef DISSENT_WEB_PACKAGERS_PACAKGER_GUARD
#define DISSENT_WEB_PACKAGERS_PACAKGER_GUARD

#include <QVariant>

#include "Web/HttpResponse.hpp"

namespace Dissent {
namespace Web {
namespace Packagers {

  /**
   * Packagers seralize WebService output data 
   * (in the form of QVariant objects) into byte 
   * streams so that they can be written to HTTP connections
   */
  class Packager : public QObject {
    Q_OBJECT

    public:
    
      virtual ~Packager() {};

      /**
       * Serialize the data represented by vardata into the 
       * HttpResponse object (response). Returns true if
       * serialization was successful and false otherwise.
       * Might change the status code of the response.
       *
       * @param the data to serialize
       * @param the HTTP Response into which the data should be
       *        serialized
       */
      virtual bool Package(QVariant &vardata, HttpResponse &response) = 0;

  };

}
}
}

#endif
