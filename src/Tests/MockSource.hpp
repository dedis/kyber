#ifndef DISSENT_TESTS_MOCK_SOURCE_H_GUARD
#define DISSENT_TESTS_MOCK_SOURCE_H_GUARD

#include "Dissent.hpp"

class MockSource : public SourceObject {
  public:
    void IncomingData(const QSharedPointer<ISender> &from,
        const QByteArray &data)
    {
      PushData(from, data);
    }
};

#endif
