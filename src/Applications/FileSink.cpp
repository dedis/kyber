#include "FileSink.hpp"

#include "Messaging/ISender.hpp"

namespace Dissent {
namespace Applications {
  FileSink::FileSink(const QString &filename) :
      m_file(filename),
      m_valid(true)
  {
    if(!m_file.open(QIODevice::WriteOnly | QIODevice::Text)) {
      m_valid = false;
      return;
    }

    m_out.setDevice(&m_file);
  }

  bool FileSink::IsValid()
  {
    return m_valid;
  }

  void FileSink::HandleData(const QSharedPointer<ISender> &from, const QByteArray &data)
  {
    m_out << from->ToString() << data.data();
  }
}
}
