#ifndef DISSENT_CRYPTO_LRS_SIGNATURE_H_GUARD
#define DISSENT_CRYPTO_LRS_SIGNATURE_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QVariant>

#include "Integer.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * A class for passing around, serializing, and deseriaizing a LRS Signature
   */
  class LRSSignature {
    public:
      explicit LRSSignature(const QByteArray &sig)
      {
        QVariantList list;
        QDataStream stream(sig);

        QByteArray bcommit_1;
        stream >> bcommit_1;
        if(bcommit_1.size() == 0) {
          qDebug() << "Missing commit";
          _valid = false;
          return;
        }   
            
        QList<QByteArray> bsignatures;
        stream >> bsignatures;
        if(bsignatures.size() <= 1) {
          qDebug() << "Not enough signatures.";
          _valid = false;
          return;
        }

        QByteArray btag;
        stream >> btag;
        if(btag.size() == 0) {
          qDebug() << "Missing tag";
          _valid = false;
          return;
        }

        _commit_1 = Integer(bcommit_1);

        foreach(const QByteArray &signature, bsignatures) {
          if(signature.size() == 0) {
            qDebug() << "Bad signature";
            _valid = false;
            return;
          }
          _signatures.append(Integer(signature));
        }
            
        _tag = Integer(btag);
        _valid = true;
     }

      explicit LRSSignature(const Integer &commit_1,
          const QVector<Integer> &signatures,
          const Integer &tag) :
        _commit_1(commit_1),
        _signatures(signatures),
        _tag(tag),
        _valid(true)
      {
      }

      QByteArray GetByteArray() const
      {
        QByteArray signature;
        QDataStream stream(&signature, QIODevice::WriteOnly);
        stream << _commit_1;
        stream << _signatures;
        stream << _tag;
        
        return signature;
      }


      bool IsValid() const { return _valid; }
      Integer GetCommit1() const { return _commit_1; }
      Integer GetSignature(int idx) const { return _signatures[idx]; }
      int SignatureCount() const { return _signatures.count(); }
      Integer GetTag() const { return _tag; }

    private:
      Integer _commit_1;
      QVector<Integer> _signatures;
      Integer _tag;
      bool _valid;
  };
}
}

#endif
