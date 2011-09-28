#include "Id.hpp"

namespace Dissent {
namespace Connections {
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
      throw std::runtime_error("Bitsize too large: " + iid.BitCount());
    }

    _data = QExplicitlySharedDataPointer<IdData>(new IdData(bid, iid, sid));
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
    QByteArray bid = QByteArray::fromBase64(sid.toLocal8Bit()).data();
    return bid;
  }

  inline const Integer Id::GetInteger(const QByteArray &bid)
  {
    Integer iid(reinterpret_cast<const byte *>(bid.data()), ByteSize);
    return iid;
  }

  inline const QString Id::GetQString(const QByteArray &bid)
  {
    QString sid(bid.toBase64());
    return sid;
  }
}
}
