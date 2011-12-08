
#include <QByteArray>
#include <QDebug>

#include "json.h"

#include "JsonPackager.hpp"

namespace Dissent {
namespace Web {
namespace Packagers {

  JsonPackager::JsonPackager() {};

  JsonPackager::~JsonPackager() {};

  bool JsonPackager::Package(QVariant &vardata, HttpResponse &response)
  {
    //response.AddHeader("Content-Type", "application/json");

    bool retval;
    QByteArray arr = QtJson::Json::serialize(vardata, retval);
    if(!retval) return false;

    response.body << arr;
    response.body << "\n";

    return true;
  }

}
}
}
