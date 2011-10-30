#include "ConsoleSink.hpp"
#include <QDebug>

namespace Dissent {
namespace Applications {
  ConsoleSink::ConsoleSink() :
      _qtout(stdout, QIODevice::WriteOnly)
  {
  }

  void ConsoleSink::HandleData(const QByteArray &data, ISender *from)
  {
    QString msg = QString::fromUtf8(data.data());
    _qtout << endl << "Incoming data: " << from->ToString() << " " << msg << endl;
  }
}
}
