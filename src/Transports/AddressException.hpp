#ifndef DISSENT_TRANSPORTS_ADDRESS_EXCEPTION_H_GUARD
#define DISSENT_TRANSPORTS_ADDRESS_EXCEPTION_H_GUARD

#include <string>
#include <stdexcept>

#include <QString>

namespace Dissent {
namespace Transports {
  class AddressException : public std::runtime_error {
    public:
      AddressException(const QString& what_arg) : std::runtime_error(what_arg.toUtf8().data()) { }
  };
}
}

#endif
