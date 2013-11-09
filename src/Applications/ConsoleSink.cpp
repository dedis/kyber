#include <QDebug>

#include "Messaging/ISender.hpp"

#include "ConsoleSink.hpp"

using Dissent::Messaging::ISender;

namespace Dissent {
namespace Applications {
  ConsoleSink::ConsoleSink() :
      m_qtout(stdout, QIODevice::WriteOnly)
  {
  }

  void ConsoleSink::HandleData(const QSharedPointer<ISender> &from,
      const QByteArray &data)
  {
    QString msg = QString::fromUtf8(data.data());
    m_qtout << endl << "Incoming data: " << from->ToString() << " " << msg << endl;
  }
}
}
