#include "Id.hpp"
#include <QDebug>

namespace Dissent {
namespace Connections {
  const Id Id::Zero = Id(Integer(long(0)));

  Id::Id()
  {
    CryptoPP::AutoSeededX917RNG<CryptoPP::DES_EDE3> rng;
    Integer iid(rng, Id::BitSize);
    QByteArray bid = Id::GetQByteArray(iid);
    Init(bid, iid, Id::GetQString(bid));
  }
  
  Id::Id(const QByteArray &bid)
  {
    Init(bid, Id::GetInteger(bid), Id::GetQString(bid));
  }

  Id::Id(const Integer &iid)
  {
    QByteArray bid = Id::GetQByteArray(iid);
    Init(bid, iid, Id::GetQString(bid));
  }

  Id::Id(const QString &sid)
  {
    QByteArray bid = Id::GetQByteArray(sid);
    Init(bid, Id::GetInteger(bid), sid);
  }

  void Id::Init(const QByteArray &bid, const Integer &iid, const QString &sid)
  {
    if(iid.BitCount() > BitSize) {
      qCritical() << "Bitsize too large:" << iid.BitCount();
    }

    QByteArray rbid = bid;
    if(uint(rbid.size()) != ByteSize) {
      rbid = GetQByteArray(iid);
    }

    _data = new IdData(rbid, iid, sid);
  }

  QString Id::ToString() const
  {
    return _data->sid;
  }

  bool Id::operator==(const Id &other) const
  {
    return _data->iid == other._data->iid;
  }

  bool Id::operator!=(const Id &other) const
  {
    return _data->iid != other._data->iid;
  }

  bool Id::operator<(const Id &other) const
  {
    return _data->iid < other._data->iid;
  }

  bool Id::operator>(const Id &other) const
  {
    return _data->iid > other._data->iid;
  }

  inline const QByteArray Id::GetQByteArray(const Integer &iid)
  {
    QByteArray bid(20, 0);
    iid.Encode(reinterpret_cast<byte *>(bid.data()), ByteSize);
    return bid;
  }

  inline const QByteArray Id::GetQByteArray(const QString &sid)
  {
    const QChar *chs = sid.data();
    QByteArray tmp;
    int idx = 0;
    for(; chs[idx] != '\0'; idx++) {
      tmp.append(chs[idx].cell());
    }

    QByteArray bid = QByteArray::fromBase64(tmp);
    return bid;
  }

  inline const Integer Id::GetInteger(const QByteArray &bid)
  {
    Integer iid(reinterpret_cast<const byte *>(bid.data()), bid.size());
    return iid;
  }

  inline const QString Id::GetQString(const QByteArray &bid)
  {
    QString sid(bid.toBase64());
    return sid;
  }
}
}
