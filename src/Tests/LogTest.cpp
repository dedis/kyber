#include "DissentTest.hpp"

#include <QByteArray>
#include <QDataStream>

using Dissent::Anonymity::Log;
using Dissent::Connections::Id;
using Dissent::Utils::Random;

namespace Dissent {
namespace Tests {
  TEST(Log, Base)
  {
    QVector<QByteArray> msgs;
    QVector<Id> ids;

    Id id;
    QByteArray data(100, 0);
    Library *lib = CryptoFactory::GetInstance().GetLibrary();
    QScopedPointer<Dissent::Utils::Random> rand(lib->GetRandomNumberGenerator());

    Log log;

    for(int idx = 0; idx < 100; idx++) {
      rand->GenerateBlock(data);
      msgs.append(data);
      id = Id();
      ids.append(id);
      log.Append(data, id);
    }

    QByteArray out_data;
    QDataStream out_stream(&out_data, QIODevice::WriteOnly);
    out_stream << log.Serialize();

    QDataStream in_stream(out_data);
    QByteArray in_data;
    in_stream >> in_data;

    Log out_log(log.Serialize());
    Log in_log(in_data);

    EXPECT_EQ(log.Count(), 100);
    EXPECT_EQ(msgs.count(), 100);
    EXPECT_EQ(in_log.Count(), 100);
    EXPECT_EQ(out_log.Count(), 100);

    for(int idx = 0; idx < 100; idx++) {
      Id id0;
      QByteArray data0;
      log.At(idx, data0, id0);

      EXPECT_EQ(data0, msgs[idx]);
      EXPECT_EQ(id0, ids[idx]);

      Id id1;
      QByteArray data1;

      in_log.At(idx, data1, id1);
      EXPECT_EQ(data0, data1);
      EXPECT_EQ(id0, id1);

      out_log.At(idx, data1, id1);
      EXPECT_EQ(data0, data1);
      EXPECT_EQ(id0, id1);
    }
  }
}
}
