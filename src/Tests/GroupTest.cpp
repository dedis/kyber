#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Group, Basic)
  {
    QVector<Id> id(10);

    QVector<PublicIdentity> gr;
    for(int idx = 0; idx < 10; idx++) {
      gr.append(PublicIdentity(id[idx], Group::EmptyKey(),
            Group::EmptyKey(), QByteArray()));
    }

    qSort(id);
    Group group(gr);

    EXPECT_EQ(group.Count(), 10);
    for(int idx = 0; idx < 10; idx++) {
      EXPECT_EQ(id[idx], group.GetId(idx));
      EXPECT_EQ(idx, group.GetIndex(id[idx]));
      EXPECT_TRUE(group.Contains(id[idx]));
      if(idx == 9) {
        EXPECT_EQ(group.Next(id[idx]), Id::Zero());
        EXPECT_EQ(group.Previous(id[idx]), group.GetId(idx - 1));
      } else if(idx == 0) {
        EXPECT_EQ(group.Next(id[idx]), group.GetId(idx + 1));
        EXPECT_EQ(group.Previous(id[idx]), Id::Zero());
      } else {
        EXPECT_EQ(group.Next(id[idx]), group.GetId(idx + 1));
        EXPECT_EQ(group.Previous(id[idx]), group.GetId(idx - 1));
      }
    }

    Id id0;
    EXPECT_FALSE(group.Contains(id0));

    QVector<PublicIdentity> gr0;
    for(int idx = 9; idx >= 0; idx--) {
      gr0.append(PublicIdentity(Id(), Group::EmptyKey(),
            Group::EmptyKey(), QByteArray()));
    }
    Group group0(gr0);
    for(int idx = 0; idx < 10; idx++) {
      EXPECT_NE(group.GetId(idx), group0.GetId(idx));
      EXPECT_EQ(group.GetId(idx), group.GetId(idx));
      EXPECT_EQ(group0.GetId(idx), group0.GetId(idx));
    }
  }

  PublicIdentity CreateMember(const Id &id = Id())
  {
    QByteArray bid = id.GetByteArray();
    QSharedPointer<AsymmetricKey> key(new RsaPrivateKey(bid, true));
    DiffieHellman dh;
    return PublicIdentity(id, key, key, dh.GetPublicComponent());
  }

  void AddMember(QVector<PublicIdentity> &group, const Id &id = Id())
  {
    group.append(CreateMember(id));
  }

  TEST(Group, Serialization)
  {
    QVector<PublicIdentity> gr;
    for(int idx = 0; idx < 100; idx++) {
      AddMember(gr);
    }

    Group group_in(gr);

    QByteArray msg;
    QDataStream stream_in(&msg, QIODevice::WriteOnly);

    stream_in << group_in;

    QDataStream stream_out(msg);
    Group group_out;
    stream_out >> group_out;

    EXPECT_EQ(group_in, group_out);
    EXPECT_EQ(gr[0], gr[0]);
    EXPECT_NE(gr[1], gr[0]);

    foreach(const PublicIdentity &gc, group_in) {
      EXPECT_TRUE(group_out.Contains(gc.GetId()));
    }

    foreach(const PublicIdentity &gc, group_out) {
      EXPECT_TRUE(group_in.Contains(gc.GetId()));
    }

    EXPECT_TRUE(IsSubset(group_in, group_out));
  }

  TEST(Group, Subgroup)
  {
    QVector<PublicIdentity> gr;
    for(int idx = 0; idx < 100; idx++) {
      AddMember(gr);
    }

    Group set(gr);
    QVector<PublicIdentity> gr0;

    for(int idx = 0; idx < 10; idx++) {
      int offset = Random::GetInstance().GetInt(10 * idx, 10 + 10 * idx);
      gr0.append(set.GetIdentity(offset));
    }

    Group subset(gr0);

    EXPECT_TRUE(IsSubset(subset, subset));
    ASSERT_TRUE(IsSubset(set, subset));
    EXPECT_FALSE(IsSubset(subset, set));
  }

  TEST(Group, Mutable)
  {
    QVector<PublicIdentity> gr;
    for(int idx = 0; idx < 10; idx++) {
      Id id;
      gr.append(PublicIdentity(id, Group::EmptyKey(),
            Group::EmptyKey(), QByteArray()));
    }

    Group group(gr);
    Group removed(gr);

    EXPECT_EQ(group.GetRoster(), removed.GetRoster());
    EXPECT_TRUE(IsSubset(group, removed));
    int count;
    while((count = removed.Count())) {
      int idx = Random::GetInstance().GetInt(0, count);
      removed = RemoveGroupMember(removed, removed.GetId(idx));
      EXPECT_NE(group.GetRoster(), removed.GetRoster());
      EXPECT_TRUE(IsSubset(group, removed));
    }
  }

  TEST(Group, JoinsAndLoses)
  {
    QVector<PublicIdentity> gr;
    for(int idx = 0; idx < 100; idx++) {
      AddMember(gr);
    }

    Group group(gr);

    QVector<PublicIdentity> lost, gained;
    EXPECT_FALSE(Difference(group, group, lost, gained));

    Group lost_group(group.GetRoster());
    Group lost_and_added_group(group.GetRoster());
    Group added_group(group.GetRoster());
    Group nc_group(group);

    QVector<Id> removed;
    for(int i = 0; i < 10; i++) {
      int idx = Random::GetInstance().GetInt(0, lost_group.Count());
      Id id = lost_group.GetId(idx);
      removed.append(id);
      lost_group = RemoveGroupMember(lost_group, id);
      lost_and_added_group = RemoveGroupMember(lost_and_added_group, id);
    }

    QVector<Id> added;
    for(int i = 0; i < 10; i++) {
      Id id;
      added.append(id);
      PublicIdentity gc = CreateMember(id);
      lost_and_added_group = AddGroupMember(lost_and_added_group, gc);
      added_group = AddGroupMember(added_group, gc);
    }

    EXPECT_EQ(nc_group, group);
    EXPECT_NE(lost_group, group);
    EXPECT_NE(lost_and_added_group, group);
    EXPECT_NE(added_group, group);

    EXPECT_FALSE(Difference(group, nc_group, lost, gained));

    QVector<PublicIdentity> lost0, gained0;
    EXPECT_TRUE(Difference(group, lost_and_added_group, lost, gained));
    EXPECT_TRUE(Difference(group, lost_group, lost0, gained0));
    EXPECT_EQ(lost0, lost);
    EXPECT_NE(gained, gained0);
    EXPECT_TRUE(Difference(group, added_group, lost0, gained0));
    EXPECT_NE(lost0, lost);
    EXPECT_EQ(gained, gained0);
  }

  TEST(Group, ManagedGroup)
  {
    CryptoRandom rand;
    QVector<PublicIdentity> gr;
    QVector<PublicIdentity> sgr;
    for(int idx = 0; idx < 100; idx++) {
      AddMember(gr);
      if(((double(rand.GetInt(0, 1000))) / 1000.0) < .5) {
        sgr.append(gr.last());
      }
    }

    ASSERT_NE(gr, sgr);
    Group group(gr, gr[5].GetId(), Group::ManagedSubgroup, sgr);
    ASSERT_TRUE(IsSubset(group, group.GetSubgroup()));

    PublicIdentity gc0 = CreateMember();
    group = AddGroupMember(group, gc0, true);
    ASSERT_TRUE(group.Contains(gc0.GetId()));
    ASSERT_TRUE(group.GetSubgroup().Contains(gc0.GetId()));

    PublicIdentity gc1 = CreateMember();
    group = AddGroupMember(group, gc1, false);
    ASSERT_TRUE(group.Contains(gc1.GetId()));
    ASSERT_FALSE(group.GetSubgroup().Contains(gc1.GetId()));

    int to_remove = rand.GetInt(0, group.GetSubgroup().Count());
    while(to_remove == group.GetSubgroup().GetIndex(gc0.GetId())) {
      to_remove = rand.GetInt(0, group.GetSubgroup().Count());
    }
    Id id0 = group.GetSubgroup().GetId(to_remove);
    group = RemoveGroupMember(group, id0);

    ASSERT_TRUE(group.Contains(gc0.GetId()));
    ASSERT_TRUE(group.GetSubgroup().Contains(gc0.GetId()));
    ASSERT_TRUE(group.Contains(gc1.GetId()));
    ASSERT_FALSE(group.GetSubgroup().Contains(gc1.GetId()));
    ASSERT_FALSE(group.Contains(id0));
    ASSERT_FALSE(group.GetSubgroup().Contains(id0));

    to_remove = rand.GetInt(0, group.Count());
    Id id1 = group.GetId(to_remove);
    while(id1 == gc1.GetId() || group.GetSubgroup().Contains(id1)) {
      to_remove = rand.GetInt(0, group.Count());
      id1 = group.GetId(to_remove);
    }

    ASSERT_FALSE(group.GetSubgroup().Contains(id1));
    group = RemoveGroupMember(group, id1);

    ASSERT_TRUE(group.Contains(gc0.GetId()));
    ASSERT_TRUE(group.GetSubgroup().Contains(gc0.GetId()));
    ASSERT_TRUE(group.Contains(gc1.GetId()));
    ASSERT_FALSE(group.GetSubgroup().Contains(gc1.GetId()));
    ASSERT_FALSE(group.Contains(id0));
    ASSERT_FALSE(group.GetSubgroup().Contains(id0));
    ASSERT_FALSE(group.Contains(id1));
    ASSERT_FALSE(group.GetSubgroup().Contains(id1));

    QByteArray data;
    QDataStream stream_in(&data, QIODevice::WriteOnly);
    stream_in << group;

    QDataStream stream_out(data);
    Group group0;
    stream_out >> group0;

    EXPECT_EQ(group, group0);
  }
}
}
