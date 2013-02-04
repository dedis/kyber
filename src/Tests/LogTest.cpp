#include <QByteArray>
#include <QDataStream>

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Log, Base)
  {
    QVector<QByteArray> msgs;
    QVector<Id> ids;

    Id id;
    QByteArray data(100, 0);
    CryptoRandom rand;

    Log log;

    for(int idx = 0; idx < 100; idx++) {
      rand.GenerateBlock(data);
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
      QPair<QByteArray, Id> entry0 = log.At(idx);

      EXPECT_EQ(entry0.first, msgs[idx]);
      EXPECT_EQ(entry0.second, ids[idx]);

      QPair<QByteArray, Id> entry1 = in_log.At(idx);
      EXPECT_EQ(entry0.first, entry1.first);
      EXPECT_EQ(entry0.second, entry1.second);

      entry1 = out_log.At(idx);
      EXPECT_EQ(entry0.first, entry1.first);
      EXPECT_EQ(entry0.second, entry1.second);
    }

    log.ToggleEnabled();
    log.Append(data, id);
    EXPECT_EQ(log.Count(), in_log.Count());
    log.ToggleEnabled();
    log.Append(data, id);
    EXPECT_NE(log.Count(), in_log.Count());
  }
}
}
