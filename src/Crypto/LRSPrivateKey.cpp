#include "Utils/Random.hpp"

#include "DsaPrivateKey.hpp"
#include "CryptoRandom.hpp"
#include "Hash.hpp"
#include "LRSPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  LRSPrivateKey::LRSPrivateKey(
          const DsaPrivateKey &private_key,
      const QVector<DsaPublicKey> &public_keys,
      const QByteArray &linkage_context) :
    LRSPublicKey(public_keys, linkage_context)
  {
    if(!IsValid()) {
      return;
    }

    _private_key = private_key.GetPrivateExponent();
    if(GetGenerator() != private_key.GetGenerator() ||
        GetModulus() != private_key.GetModulus() ||
        GetSubgroupOrder() != private_key.GetSubgroupOrder())
    {
      qCritical() << "Invalid key parameters in LRSPublicKey";
      SetInvalid();
      return;
    }

    _my_idx = GetKeys().indexOf(private_key.GetPublicElement());
    _tag = GetGroupGenerator().Pow(_private_key, GetModulus());
  }

  void LRSPrivateKey::SetLinkageContext(const QByteArray &linkage_context)
  {
    LRSPublicKey::SetLinkageContext(linkage_context);
    _tag = GetGroupGenerator().Pow(_private_key, GetModulus());
  }

  /**
   * group_gen = Hash(Identities, linkage_context)
   * precompute = Hash(group_gen, tag, message)
   * tag = group_gen ^ private_key
   *
   * u, s_i (where i != pi) \in_R Z_q
   * c_my_idx = H(precompute, g^u, group_gen^u)
   * for(pi + 1, n) and (1, pi - 1)
   *   c_{i+1}  = H(precompute, g^s_i * y_i^c_i, h^s_i * tag^c_i)
   * s_my_idx = u - x_my_idx * c_my_idx
   * [c_1, [s_1, ..., s_n], tag] = signature
   */
  QByteArray LRSPrivateKey::Sign(const QByteArray &data) const
  {
    Hash hashalgo;

    hashalgo.Update(GetGroupGenerator().GetByteArray());
    hashalgo.Update(_tag.GetByteArray());
    hashalgo.Update(data);
    QByteArray precompute = hashalgo.ComputeHash();

    Integer u = RandomInQ();

    hashalgo.Update(precompute);
    hashalgo.Update(GetGenerator().Pow(u, GetModulus()).GetByteArray());
    hashalgo.Update(GetGroupGenerator().Pow(u, GetModulus()).GetByteArray());
    Integer commit = Integer(hashalgo.ComputeHash()) % GetSubgroupOrder();
    
    QVector<Integer> keys = GetKeys();
    const int max = keys.count();
    QVector<Integer> signatures(max);
    Integer commit_1;

    if(_my_idx == max - 1) {
      commit_1 = commit;
    }

    for(int idx = 1; idx < max; idx++) {
      int fixed_idx = (idx + _my_idx) % max;
      Integer sign = RandomInQ();
      signatures[fixed_idx] = sign;

      hashalgo.Update(precompute);

      Integer tmp = (GetGenerator().Pow(sign, GetModulus()) *
          keys[fixed_idx].Pow(commit, GetModulus())) % GetModulus();
      hashalgo.Update(tmp.GetByteArray());

      tmp = (GetGroupGenerator().Pow(sign, GetModulus()) *
          _tag.Pow(commit, GetModulus())) % GetModulus();
      hashalgo.Update(tmp.GetByteArray());

      commit = Integer(hashalgo.ComputeHash()) % GetSubgroupOrder();
      if(fixed_idx == max - 1) {
        commit_1 = commit;
      }
    }

    Integer s_my_idx = (u - _private_key * commit) % GetSubgroupOrder();
    signatures[_my_idx] = s_my_idx;

    return LRSSignature(commit_1, signatures, _tag).GetByteArray();
  }

  Integer LRSPrivateKey::RandomInQ() const
  {
    QByteArray q = GetSubgroupOrder().GetByteArray();
    CryptoRandom().GenerateBlock(q);
    Integer rinq(q);
    return rinq % GetSubgroupOrder();
  }

  bool LRSPrivateKey::operator==(const AsymmetricKey &key) const
  {
    const LRSPrivateKey *other = dynamic_cast<const LRSPrivateKey *>(&key);
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
      (other->IsValid() == IsValid()) &&
      (other->_private_key == _private_key);
  }
}
}
