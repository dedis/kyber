#ifndef DISSENT_WEB_PACKAGERS_JSON_PACKAGER_GUARD
#define DISSENT_WEB_PACKAGERS_JSON_PACKAGER_GUARD

#include "Packager.hpp"

namespace Dissent {
namespace Web {
namespace Packagers {

  /**
   * A JSON serializer for returning
   * data in JSON over HTTP 
   */
  class JsonPackager : Packager {
    Q_OBJECT

    public:
      JsonPackager(); 

      ~JsonPackager();
      
      bool Package(QVariant &vardata, HttpResponse &response);

  };

}
}
}

#endif

