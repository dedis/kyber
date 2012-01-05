#include <QDebug>

#include "Messaging/ISender.hpp"

#include "ConsoleSink.hpp"

using Dissent::Messaging::ISender;

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
