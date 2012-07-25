#include "CppDsaPublicKey.hpp"
#include "CppHash.hpp"
#include "LRSPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  LRSPublicKey::LRSPublicKey(
      const QVector<QSharedPointer<AsymmetricKey> > &public_keys,
      const QByteArray &linkage_context) :
    _valid(true)
  {
    if(public_keys.count() == 0) {
      qCritical() << "Attempted at creating a LRSPublicKey";
      SetInvalid();
      return;
    }

    QSharedPointer<CppDsaPublicKey> key = public_keys[0].dynamicCast<CppDsaPublicKey>();
    if(!key) {
      qCritical() << "Attempted at using a non-dsa key in LRS";
      SetInvalid();
      return;
    }

    _generator = key->GetGenerator();
    _modulus = key->GetModulus();
    _subgroup = key->GetSubgroup();

    foreach(const QSharedPointer<AsymmetricKey> &key, public_keys) {
      if(!AddKey(key)) {
        SetInvalid();
        return;
      }
    }

    SetLinkageContext(linkage_context);
    _valid = true;
  }

  LRSPublicKey::LRSPublicKey(const QVector<Integer> &public_keys,
      const Integer &generator, const Integer &modulus,
      const Integer &subgroup, const QByteArray &linkage_context) :
    _keys(public_keys),
    _generator(generator),
    _modulus(modulus),
    _subgroup(subgroup),
    _valid(true)
  {
    if(_keys.count() == 0) {
      qCritical() << "Attempted at creating a LRSPublicKey";
      SetInvalid();
      return;
    }

    SetLinkageContext(linkage_context);
  }

  bool LRSPublicKey::AddKey(const QSharedPointer<AsymmetricKey> &key)
  {
    QSharedPointer<CppDsaPublicKey> dsa = key.dynamicCast<CppDsaPublicKey>();
    if(!dsa) {
      qCritical() << "Attempted at using a non-dsa key in LRS";
      return false;
    }

    if(dsa->GetGenerator() != GetGenerator() ||
        dsa->GetModulus() != GetModulus() ||
        dsa->GetSubgroup() != GetSubgroup())
    {
      qCritical() << "Invalid key parameters in LRSPublicKey";
      return false;
    }

    _keys.append(dsa->GetPublicElement());
    return true;
  }

  void LRSPublicKey::SetLinkageContext(const QByteArray &linkage_context)
  {
    _linkage_context = linkage_context;
    CppHash hash;
    hash.Update(linkage_context);

    QByteArray hlc = hash.ComputeHash();
    _group_gen = GetGenerator().Pow(Integer(hlc) % GetSubgroup(), GetModulus());
  }

  /**
   * group_gen = Hash(Identities, linkage_context)
   * precompute = Hash(group_gen, tag, message)
   * tag = group_gen ^ private_key
   * [c_1, [s_1, ..., s_n], tag] = signature
   * tc_1 = c_1
   * for(1, n - 1)
   *   z_i' = g^s_i * y^c_i
   *   z_i'' = group_gen^s_i * tag^c_i
   *   tc_{i+1} = Hash(precompute, z_i', z_i'')
   * valid if c_1 == tc_n
   */
  bool LRSPublicKey::Verify(const QByteArray &data, const QByteArray &sig) const
  {
    QVariantList list;
    QDataStream stream(sig);

    QByteArray bcommit_1;
    stream >> bcommit_1;
    if(bcommit_1.size() == 0) {
      qDebug() << "Missing commit";
      return false;
    }

    QList<QByteArray> bsignatures;
    stream >> bsignatures;
    QVector<Integer> keys = GetKeys();
    if(bsignatures.size() != keys.size()) {
      qDebug() << "Signatures:" << bsignatures.size() << "Keys:" << keys.size();
      return false;
    }

    QByteArray btag;
    stream >> btag;
    if(btag.size() == 0) {
      qDebug() << "Missing tag";
      return false;
    }

    Integer commit_1(bcommit_1);

    QVector<Integer> signatures;
    foreach(const QByteArray &signature, bsignatures) {
      if(signature.size() == 0) {
        qDebug() << "Bad signature";
        return false;
      }
      signatures.append(Integer(signature));
    }

    Integer tag = Integer(btag);

    CppHash hash;
    hash.Update(GetGroupGenerator().GetByteArray());
    hash.Update(btag);
    hash.Update(data);
    QByteArray precompute = hash.ComputeHash();

    Integer tcommit = commit_1;

    for(int idx = 0; idx < keys.count(); idx++) {
      Integer z_p = (GetGenerator().Pow(signatures[idx], GetModulus()) *
          _keys[idx].Pow(tcommit, GetModulus())) % GetModulus();
      Integer z_pp = (GetGroupGenerator().Pow(signatures[idx], GetModulus()) *
          tag.Pow(tcommit, GetModulus())) % GetModulus();

      hash.Update(precompute);
      hash.Update(z_p.GetByteArray());
      hash.Update(z_pp.GetByteArray());
      tcommit = Integer(hash.ComputeHash()) % GetSubgroup();
    }

    return tcommit == commit_1;
  }

  bool LRSPublicKey::operator==(const AsymmetricKey &key) const
  {
    const LRSPublicKey *other = dynamic_cast<const LRSPublicKey *>(&key);
    if(!other) {
      return false;
    }

    if(this == other) {
      return true;
    }

    return (other->GetGenerator() == GetGenerator()) &&
      (other->GetKeys() == GetKeys()) &&
      (other->GetModulus() == GetModulus()) &&
      (other->GetSubgroup() == GetSubgroup()) &&
      (other->GetLinkageContext() == GetLinkageContext()) &&
      (other->IsValid() == IsValid());
  }

  bool LRSPublicKey::VerifyKey(AsymmetricKey &key) const
  {
    if(key.IsPrivateKey() ^ !IsPrivateKey()) {
      return false;
    }

    QSharedPointer<AsymmetricKey> key0(GetPublicKey());
    QSharedPointer<AsymmetricKey> key1(key.GetPublicKey());
    return key0 == key1;
  }
}
}
