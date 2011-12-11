#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Group, Basic)
  {
    QVector<Id> id(10);

    QVector<GroupContainer> gr;
    for(int idx = 0; idx < 10; idx++) {
      gr.append(GroupContainer(id[idx], Group::EmptyKey(), QByteArray()));
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

    QVector<GroupContainer> gr0;
    for(int idx = 9; idx >= 0; idx--) {
      gr0.append(GroupContainer(Id(), Group::EmptyKey(), QByteArray()));
    }
    Group group0(gr0);
    for(int idx = 0; idx < 10; idx++) {
      EXPECT_NE(group.GetId(idx), group0.GetId(idx));
      EXPECT_EQ(group.GetId(idx), group.GetId(idx));
      EXPECT_EQ(group0.GetId(idx), group0.GetId(idx));
    }
  }

  GroupContainer CreateMember(const Id &id)
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    QByteArray bid = id.GetByteArray();
    QSharedPointer<AsymmetricKey> key(lib->GeneratePublicKey(bid));
    QScopedPointer<DiffieHellman> dh(lib->GenerateDiffieHellman(bid));
    return GroupContainer(id, key, dh->GetPublicComponent());
  }

  void AddMember(QVector<GroupContainer> &group, const Id &id = Id())
  {
    group.append(CreateMember(id));
  }

  TEST(Group, Serialization)
  {
    QVector<GroupContainer> gr;
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

    foreach(const GroupContainer &gc, group_in) {
      EXPECT_TRUE(group_out.Contains(gc.first));
    }

    EXPECT_TRUE(IsSubset(group_in, group_out));
  }

  TEST(Group, Subgroup)
  {
    QVector<GroupContainer> gr;
    for(int idx = 0; idx < 100; idx++) {
      AddMember(gr);
    }

    Group set(gr);
    QVector<GroupContainer> gr0;

    for(int idx = 0; idx < 10; idx++) {
      int offset = Random::GetInstance().GetInt(10 * idx, 10 + 10 * idx);
      AddMember(gr0, set.GetId(offset));
    }

    Group subset(gr0);

    EXPECT_TRUE(IsSubset(subset, subset));
    EXPECT_TRUE(IsSubset(set, subset));
    EXPECT_FALSE(IsSubset(subset, set));
  }

  TEST(Group, Mutable)
  {
    QVector<GroupContainer> gr;
    for(int idx = 0; idx < 10; idx++) {
      Id id;
      gr.append(GroupContainer(id, Group::EmptyKey(), QByteArray()));
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
    QVector<GroupContainer> gr;
    for(int idx = 0; idx < 100; idx++) {
      AddMember(gr);
    }

    Group group(gr);

    QVector<GroupContainer> lost, gained;
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
      GroupContainer gc = CreateMember(id);
      lost_and_added_group = AddGroupMember(lost_and_added_group, gc);
      added_group = AddGroupMember(added_group, gc);
    }

    EXPECT_EQ(nc_group, group);
    EXPECT_NE(lost_group, group);
    EXPECT_NE(lost_and_added_group, group);
    EXPECT_NE(added_group, group);

    EXPECT_FALSE(Difference(group, nc_group, lost, gained));

    QVector<GroupContainer> lost0, gained0;
    EXPECT_TRUE(Difference(group, lost_and_added_group, lost, gained));
    EXPECT_TRUE(Difference(group, lost_group, lost0, gained0));
    EXPECT_EQ(lost0, lost);
    EXPECT_NE(gained, gained0);
    EXPECT_TRUE(Difference(group, added_group, lost0, gained0));
    EXPECT_NE(lost0, lost);
    EXPECT_EQ(gained, gained0);
  }
}
}
