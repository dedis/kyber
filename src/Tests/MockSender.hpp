#ifndef DISSENT_TESTS_MOCK_SENDER_H_GUARD
#define DISSENT_TESTS_MOCK_SENDER_H_GUARD

#include <QByteArray>
#include <QSharedPointer>

#include "Dissent.hpp"
#include "MockSource.hpp"

namespace Dissent {
namespace Tests {
  class MockSender : public ISender {
    public:
      explicit MockSender(const QSharedPointer<MockSource> &source) :
        _source(source)
      {
      }

      virtual ~MockSender()
      {
      }

      virtual void Send(const QByteArray &data)
      {
        _source->IncomingData(_from.toStrongRef(), data);
      }

      void SetReturnPath(const QSharedPointer<ISender> &sender)
      {
        _from = sender.toWeakRef();
      }

    private:
      QSharedPointer<MockSource> _source;
      QWeakPointer<ISender> _from;
  };
}
}
#endif
