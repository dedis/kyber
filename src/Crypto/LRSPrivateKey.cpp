#include "Utils/Random.hpp"

#include "CppDsaPrivateKey.hpp"
#include "CppHash.hpp"
#include "LRSPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  LRSPrivateKey::LRSPrivateKey(
          const QSharedPointer<AsymmetricKey> &private_key,
      const QVector<QSharedPointer<AsymmetricKey> > &public_keys,
      const QByteArray &linkage_context) :
    LRSPublicKey(public_keys, linkage_context)
  {
    if(!IsValid()) {
      return;
    }

    QSharedPointer<CppDsaPrivateKey> key = private_key.dynamicCast<CppDsaPrivateKey>();
    if(!key) {
      qCritical() << "Attempted at using a non-dsa key in LRS";
      SetInvalid();
      return;
    }

    _private_key = key->GetPrivateExponent();
    if(GetGenerator() != key->GetGenerator() ||
        GetModulus() != key->GetModulus() ||
        GetSubgroup() != key->GetSubgroup())
    {
      qCritical() << "Invalid key parameters in LRSPublicKey";
      SetInvalid();
      return;
    }

    _my_idx = GetKeys().indexOf(key->GetPublicElement());
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
    CppHash hash;

    hash.Update(GetGroupGenerator().GetByteArray());
    hash.Update(_tag.GetByteArray());
    hash.Update(data);
    QByteArray precompute = hash.ComputeHash();

    Integer u = RandomInQ();

    hash.Update(precompute);
    hash.Update(GetGenerator().Pow(u, GetModulus()).GetByteArray());
    hash.Update(GetGroupGenerator().Pow(u, GetModulus()).GetByteArray());
    Integer commit = Integer(hash.ComputeHash()) % GetSubgroup();
    
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

      hash.Update(precompute);

      Integer tmp = (GetGenerator().Pow(sign, GetModulus()) *
          keys[fixed_idx].Pow(commit, GetModulus())) % GetModulus();
      hash.Update(tmp.GetByteArray());

      tmp = (GetGroupGenerator().Pow(sign, GetModulus()) *
          _tag.Pow(commit, GetModulus())) % GetModulus();
      hash.Update(tmp.GetByteArray());

      commit = Integer(hash.ComputeHash()) % GetSubgroup();
      if(fixed_idx == max - 1) {
        commit_1 = commit;
      }
    }

    Integer s_my_idx = (u - _private_key * commit) % GetSubgroup();
    signatures[_my_idx] = s_my_idx;

    return LRSSignature(commit_1, signatures, _tag).GetByteArray();
  }

  Integer LRSPrivateKey::RandomInQ() const
  {
    QSharedPointer<Utils::Random> rand(CryptoFactory::GetInstance().
        GetLibrary()->GetRandomNumberGenerator());
    QByteArray q = GetSubgroup().GetByteArray();
    rand->GenerateBlock(q);
    Integer rinq(q);
    return rinq % GetSubgroup();
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
      (other->GetSubgroup() == GetSubgroup()) &&
      (other->GetLinkageContext() == GetLinkageContext()) &&
      (other->IsValid() == IsValid()) &&
      (other->_private_key == _private_key);
  }
}
}
