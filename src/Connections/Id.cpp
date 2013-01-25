#include "Id.hpp"
#include "Crypto/CryptoFactory.hpp"
#include <QDebug>

using namespace Dissent::Crypto;

namespace Dissent {
namespace Connections {
  const Id &Id::Zero()
  {
    static Id zero(QByteArray(Id::ByteSize, 0));
    return zero;
  }

  Id::Id()
  {
    Library &lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rng(lib.GetRandomNumberGenerator());
    QByteArray bid(ByteSize, 0);
    rng->GenerateBlock(bid);
    _integer = Integer(bid);
  }
  
  Id::Id(const QByteArray &bid) : _integer(bid)
  {
  }

  Id::Id(const Integer &integer) : _integer(integer)
  {
  }

  Id::Id(const QString &sid) : _integer(sid)
  {
    if(_integer.ToString() != sid) {
      _integer = Zero()._integer;
    }
  }
}
}
