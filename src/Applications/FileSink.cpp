#include "../Messaging/ISender.hpp"

#include "FileSink.hpp"

using Dissent::Messaging::ISender;

namespace Dissent {
namespace Applications {
  FileSink::FileSink(const QString &filename) :
      _file(filename),
      _valid(true)
  {
    if(!_file.open(QIODevice::WriteOnly | QIODevice::Text)) {
      _valid = false;
      return;
    }

    _out.setDevice(&_file);
  }

  bool FileSink::IsValid()
  {
    return _valid;
  }

  void FileSink::HandleData(const QByteArray &data, ISender *from)
  {
    _out << from->ToString() << data.data();
  }
}
}
