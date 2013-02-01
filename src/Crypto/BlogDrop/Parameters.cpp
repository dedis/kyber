#include <QByteArray>

#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/ECParams.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Parameters.hpp"

using namespace Dissent::Crypto::AbstractGroup;

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  QSharedPointer<Parameters> Parameters::IntegerElGamalTesting() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::GetGroup(IntegerGroup::TESTING_256);
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, QByteArray(), fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::IntegerElGamalProduction(const QByteArray &round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::GetGroup(IntegerGroup::PRODUCTION_2048);
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, round_nonce, fixed, fixed, 2));
  }

  QSharedPointer<Parameters> Parameters::IntegerHashingTesting() 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::GetGroup(IntegerGroup::TESTING_256);
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, QByteArray(), fixed, fixed, 8));
  }

  QSharedPointer<Parameters> Parameters::IntegerHashingProduction(const QByteArray &round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = IntegerGroup::GetGroup(IntegerGroup::PRODUCTION_2048);
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, round_nonce, fixed, fixed, 2));
  }

  QSharedPointer<Parameters> Parameters::CppECElGamalProduction(const QByteArray &round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = CppECGroup::GetGroup(ECParams::NIST_P256);
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_ElGamal, round_nonce, fixed, fixed, 16));
  }

  QSharedPointer<Parameters> Parameters::CppECHashingProduction(const QByteArray &round_nonce) 
  {
    QSharedPointer<const AbstractGroup> fixed = CppECGroup::GetGroup(ECParams::NIST_P256);
    return QSharedPointer<Parameters>(
        new Parameters(ProofType_HashingGenerator, round_nonce, fixed, fixed, 16));
  }

  QSharedPointer<Parameters> Parameters::Empty() 
  {
    return QSharedPointer<Parameters>(new Parameters());
  }

  Parameters::Parameters() : 
    _proof_type(ProofType_Invalid),
    _n_elements(0) {}

  Parameters::Parameters(ProofType proof_type, 
      const QByteArray &round_nonce,
      const QSharedPointer<const AbstractGroup> &key_group, 
      const QSharedPointer<const AbstractGroup> &msg_group, 
      int n_elements) :
    _proof_type(proof_type),
    _round_nonce(round_nonce),
    _key_group(key_group),
    _msg_group(msg_group),
    _n_elements(n_elements)
  {
    Q_ASSERT(!_key_group.isNull());
    Q_ASSERT(!_msg_group.isNull());
    Q_ASSERT(key_group->IsProbablyValid());
    Q_ASSERT(msg_group->IsProbablyValid());
  }
  
  Parameters::Parameters(const Parameters &p) :
    _proof_type(p._proof_type),
    _round_nonce(p._round_nonce),
    _key_group(p._key_group->Copy()),
    _msg_group(p._msg_group->Copy()),
    _n_elements(p._n_elements)
  {
  }

  QByteArray Parameters::GetByteArray() const
  {
    QByteArray out;
    out += GetRoundNonce();
    out += GetKeyGroup()->GetByteArray();
    out += GetMessageGroup()->GetByteArray();
    out += _n_elements;
    return out;
  }

  QString Parameters::ProofTypeToString(ProofType pt)
  {
    QString out; 
    switch(pt) {
      case ProofType_ElGamal:
        out = "ElGamal";
        break;

      case ProofType_HashingGenerator:
        out = "HashingGenerator";
        break;

      case ProofType_Invalid:
        out = "Invalid";
        break;

      default: 
        out = "Unknown";
    }

    return out;
  }

  QString Parameters::ToString() const
  {
    return QString("Parameters<keygroup: %1, "
        "msggroup: %2, "
        "prooftype: %3, "
        "nelms: %4, "
        "nonce: \"%5\">").arg(
          _key_group->ToString()).arg(
          _msg_group->ToString()).arg(
          ProofTypeToString(GetProofType())).arg(
          _n_elements).arg( 
          QString(_round_nonce.toHex()));
  }
}
}
}
