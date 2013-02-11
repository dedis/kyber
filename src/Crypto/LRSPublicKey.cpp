#include "DsaPublicKey.hpp"
#include "Hash.hpp"
#include "LRSPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  LRSPublicKey::LRSPublicKey(
      const QVector<DsaPublicKey> &public_keys,
      const QByteArray &linkage_context) :
    m_valid(true)
  {
    if(public_keys.count() == 0) {
      qCritical() << "Attempted at creating a LRSPublicKey";
      SetInvalid();
      return;
    }

    const DsaPublicKey key = public_keys[0];
    m_generator = key.GetGenerator();
    m_modulus = key.GetModulus();
    m_subgroup = key.GetSubgroupOrder();

    foreach(const DsaPublicKey &key, public_keys) {
      if(!AddKey(key)) {
        SetInvalid();
        return;
      }
    }

    SetLinkageContext(linkage_context);
    m_valid = true;
  }

  LRSPublicKey::LRSPublicKey(const QVector<Integer> &public_keys,
      const Integer &generator, const Integer &modulus,
      const Integer &subgroup, const QByteArray &linkage_context) :
    m_keys(public_keys),
    m_generator(generator),
    m_modulus(modulus),
    m_subgroup(subgroup),
    m_valid(true)
  {
    if(m_keys.count() == 0) {
      qCritical() << "Attempted at creating a LRSPublicKey";
      SetInvalid();
      return;
    }

    SetLinkageContext(linkage_context);
  }

  bool LRSPublicKey::AddKey(const DsaPublicKey &key)
  {
    if(key.GetGenerator() != GetGenerator() ||
        key.GetModulus() != GetModulus() ||
        key.GetSubgroupOrder() != GetSubgroupOrder())
    {
      qCritical() << "Invalid key parameters in LRSPublicKey";
      return false;
    }

    m_keys.append(key.GetPublicElement());
    return true;
  }

  void LRSPublicKey::SetLinkageContext(const QByteArray &linkage_context)
  {
    m_linkage_context = linkage_context;
    Hash hashalgo;
    hashalgo.Update(linkage_context);

    QByteArray hlc = hashalgo.ComputeHash();
    m_group_gen = GetGenerator().Pow(Integer(hlc) % GetSubgroupOrder(), GetModulus());
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
    return Verify(data, LRSSignature(sig));
  }

  bool LRSPublicKey::Verify(const QByteArray &data, const LRSSignature &sig) const
  {
    if(!sig.IsValid()) {
      qDebug() << "Invalid signature";
      return false;
    }

    if(sig.SignatureCount() != GetKeys().count()) {
      qDebug() << "Incorrect amount of keys used to generate signature.";
      return false;
    }

    Hash hashalgo;
    hashalgo.Update(GetGroupGenerator().GetByteArray());
    hashalgo.Update(sig.GetTag().GetByteArray());
    hashalgo.Update(data);
    QByteArray precompute = hashalgo.ComputeHash();

    Integer tcommit = sig.GetCommit1();

    QVector<Integer> keys = GetKeys();
    for(int idx = 0; idx < keys.count(); idx++) {
      Integer z_p = (GetGenerator().Pow(sig.GetSignature(idx), GetModulus()) *
          keys[idx].Pow(tcommit, GetModulus())) % GetModulus();
      Integer z_pp = (GetGroupGenerator().Pow(sig.GetSignature(idx), GetModulus()) *
          sig.GetTag().Pow(tcommit, GetModulus())) % GetModulus();

      hashalgo.Update(precompute);
      hashalgo.Update(z_p.GetByteArray());
      hashalgo.Update(z_pp.GetByteArray());
      tcommit = Integer(hashalgo.ComputeHash()) % GetSubgroupOrder();
    }

    return tcommit == sig.GetCommit1();
  }

  bool LRSPublicKey::Equals(const AsymmetricKey &key) const
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
      (other->GetSubgroupOrder() == GetSubgroupOrder()) &&
      (other->GetLinkageContext() == GetLinkageContext()) &&
      (other->IsValid() == IsValid());
  }

  bool LRSPublicKey::VerifyKey(const AsymmetricKey &key) const
  {
    if(key.IsPrivateKey() == IsPrivateKey()) {
      return false;
    }

    return GetPublicKey()->Equals(*key.GetPublicKey());
  }
}
}
