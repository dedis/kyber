#ifdef CRYPTOPP

#include <cryptopp/integer.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/modarith.h>

#include "Crypto/Integer.hpp"
#include "Helper.hpp"

namespace Dissent {
namespace Crypto {
  class CppIntegerImpl : public IIntegerImpl {
    public:
      CppIntegerImpl(int value) : m_data(value)
      {
      }

      CppIntegerImpl(const QByteArray &value) :
        m_data(reinterpret_cast<const byte *>(value.constData()), value.size())
      {
      }

      CppIntegerImpl(const IIntegerImpl * const value) : m_data(GetData(value))
      {
      }

      CppIntegerImpl(const CryptoPP::Integer &value) : m_data(value)
      {
      }

      virtual QByteArray GetByteArray() const
      {
        int size = m_data.MinEncodedSize();
        QByteArray byte_array(size, 0);
        m_data.Encode(reinterpret_cast<byte *>(byte_array.data()), size);
        return byte_array;
      }

      virtual bool IsPrime() const
      {
        return (m_data > 0) && CryptoPP::IsPrime(m_data);
      }

      virtual IIntegerImpl *Add(const IIntegerImpl * const term) const
      {
        return new CppIntegerImpl(m_data.Plus(GetData(term)));
      }

      virtual IIntegerImpl *Subtract(const IIntegerImpl * const subtrahend) const
      {
        return new CppIntegerImpl(m_data.Minus(GetData(subtrahend)));
      }

      virtual IIntegerImpl *Multiply(const IIntegerImpl * const multiplicand) const
      {
        return new CppIntegerImpl(m_data.Times(GetData(multiplicand)));
      }

      virtual IIntegerImpl *Multiply(const IIntegerImpl * const multiplicand,
          const IIntegerImpl * const modulus) const
      {
        return new CppIntegerImpl(a_times_b_mod_c(m_data,
              GetData(multiplicand), GetData(modulus)));
      }

      virtual IIntegerImpl *Divide(const IIntegerImpl * const divisor) const
      {
        return new CppIntegerImpl(m_data.DividedBy(GetData(divisor)));
      }

      virtual IIntegerImpl *Modulo(const IIntegerImpl * const mod) const
      {
        return new CppIntegerImpl(m_data % GetData(mod));
      }

      virtual IIntegerImpl *Pow(const IIntegerImpl * const pow,
          const IIntegerImpl * const mod) const
      {
        return new CppIntegerImpl(a_exp_b_mod_c(m_data,
              GetData(pow), GetData(mod)));
      }

      virtual IIntegerImpl *PowCascade(const IIntegerImpl * const x0, const IIntegerImpl * const e0,
          const IIntegerImpl * const x1, const IIntegerImpl * const e1) const
      {
        CryptoPP::ModularArithmetic ma(m_data);
        return new CppIntegerImpl(ma.CascadeExponentiate(
              GetData(x0), GetData(e0), GetData(x1), GetData(e1)));
      }

      virtual IIntegerImpl *Inverse(const IIntegerImpl * const mod) const
      {
        return new CppIntegerImpl(m_data.InverseMod(GetData(mod)));
      }

      virtual bool Equals(const IIntegerImpl * const other) const
      {
        return m_data == GetData(other);
      }

      virtual bool LessThan(const IIntegerImpl * const other) const
      {
        return m_data < GetData(other);
      }

      virtual bool LessThanOrEqual(const IIntegerImpl * const other) const
      {
        return m_data <= GetData(other);
      }

      virtual int GetBitCount() const
      {
        return m_data.BitCount();
      }

      virtual int GetByteCount() const
      {
        return m_data.ByteCount();
      }

      virtual int GetInt32() const
      {
        return m_data.GetBits(0, 32);
      }

      static const CryptoPP::Integer &GetData(const IIntegerImpl * const value)
      {
        const CppIntegerImpl * const nv =
          dynamic_cast<const CppIntegerImpl * const>(value);
        Q_ASSERT(nv);
        return nv->m_data;
      }
    private:
      CryptoPP::Integer m_data;
  };

  Integer::Integer(int value) :
    m_data(new CppIntegerImpl(value))
  {
  }

  Integer::Integer(const QByteArray &value) :
    m_data(new CppIntegerImpl(value))
  {
  }

  Integer::Integer(const QString &value) :
    m_data(new CppIntegerImpl(Integer::FromBase64(value)))
  {
  }

  CryptoPP::Integer ToCppInteger(const Integer &value)
  {
    return CppIntegerImpl::GetData(value.GetHandle());
  }

  Integer FromCppInteger(const CryptoPP::Integer &value)
  {
    return Integer(new CppIntegerImpl(value));
  }
}
}

#endif
