#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Settings, Basic)
  {
    Id id;
    QFile file("dissent.ini");
    file.remove();

    Settings settings("dissent.ini", false);
    EXPECT_EQ(settings.LocalEndPoints.count(), 0);
    EXPECT_EQ(settings.RemotePeers.count(), 0);
    settings.LocalEndPoints.append(QUrl("buffer://5"));
    settings.RemotePeers.append(QUrl("buffer://6"));
    settings.LocalIds = QList<Id>();
    settings.LocalIds.append(id);
    settings.Save();

    Settings settings0("dissent.ini", false);
    EXPECT_EQ(settings0.LocalEndPoints.count(), 1);
    EXPECT_EQ(settings0.RemotePeers.count(), 1);
    EXPECT_EQ(settings0.LocalEndPoints[0], QUrl("buffer://5"));
    EXPECT_EQ(settings0.RemotePeers[0], QUrl("buffer://6"));
    settings0.LocalEndPoints.append(QUrl("buffer://7"));
    settings0.RemotePeers.append(QUrl("buffer://8"));
    settings0.Save();

    QStringList settings_list0;
    settings_list0 << "dissent" << "dissent.ini";
    Settings settings1 = Settings::CommandLineParse(settings_list0);
    EXPECT_EQ(settings1.LocalEndPoints.count(), 2);
    EXPECT_EQ(settings1.RemotePeers.count(), 2);
    EXPECT_EQ(settings1.LocalEndPoints[0], QUrl("buffer://5"));
    EXPECT_EQ(settings1.LocalEndPoints[1], QUrl("buffer://7"));
    EXPECT_EQ(settings1.RemotePeers[0], QUrl("buffer://6"));
    EXPECT_EQ(settings1.RemotePeers[1], QUrl("buffer://8"));
    EXPECT_EQ(id, settings1.LocalIds[0]);

    QStringList settings_list;
    settings_list << "application" << "--remote_peers" << "buffer://5" <<
      "--remote_peers" << "buffer://6" <<
      "--endpoints" << "buffer://4" << "--local_nodes" << "3" <<
      "--auth_mode" << "null" << "--session_type" << "csbulk" <<
      "--log" << "stderr" << "--console" <<
      "--web_server_url" << "http://127.0.0.1:8000" <<
      "--entry_tunnel_url" << "tcp://127.0.0.1:8081" <<
      "--exit_tunnel" << "--multithreading" <<
      "--local_id" << "'HJf+qfK7oZVR3dOqeUQcM8TGeVA='" <<
      "--subgroup_policy" << "ManagedSubgroup" <<
      "--super_peer";

    Settings settings2 = Settings::CommandLineParse(settings_list, false);

    EXPECT_EQ(settings2.LocalEndPoints.count(), 1);
    EXPECT_EQ(settings2.LocalEndPoints[0], QUrl("buffer://4"));
    EXPECT_EQ(settings2.RemotePeers.count(), 2);
    EXPECT_EQ(settings2.RemotePeers[0], QUrl("buffer://5"));
    EXPECT_EQ(settings2.RemotePeers[1], QUrl("buffer://6"));
    EXPECT_EQ(settings2.LocalNodeCount, 3);
    EXPECT_EQ(settings2.AuthMode, AuthFactory::NULL_AUTH);
    EXPECT_EQ(settings2.SessionType, "csbulk");
    EXPECT_EQ(settings2.Log, "stderr");
    EXPECT_TRUE(settings2.Console);
    EXPECT_EQ(settings2.WebServerUrl, QUrl("http://127.0.0.1:8000"));
    EXPECT_TRUE(settings2.WebServer);
    EXPECT_EQ(settings2.EntryTunnelUrl, QUrl("tcp://127.0.0.1:8081"));
    EXPECT_TRUE(settings2.EntryTunnel);
    EXPECT_TRUE(settings2.ExitTunnel);
    EXPECT_TRUE(settings2.Multithreading);
    EXPECT_TRUE(settings2.SuperPeer);
  }

  TEST(Settings, Invalid)
  {
    Settings settings;
    EXPECT_FALSE(settings.IsValid());

    settings.LocalEndPoints.append(QUrl("buffer://5"));
    EXPECT_FALSE(settings.IsValid());

    settings.LeaderId = Id();
    EXPECT_TRUE(settings.IsValid());

    settings.SubgroupPolicy = static_cast<Group::SubgroupPolicy>(-1);
    EXPECT_FALSE(settings.IsValid());

    settings.SubgroupPolicy = Group::CompleteGroup;
    EXPECT_TRUE(settings.IsValid());
  }

  TEST(Settings, WebServer)
  {
    Settings settings;
    settings.LocalEndPoints.append(QUrl("buffer://5"));
    settings.LeaderId = Id();
    EXPECT_TRUE(settings.IsValid());

    settings.WebServer = true;

    settings.WebServerUrl = "xyz://127.1.34.1:-y";
    EXPECT_FALSE(settings.IsValid());

    settings.WebServerUrl = "xyz://127.1.34.1:8080";
    EXPECT_TRUE(settings.IsValid());

    settings.WebServerUrl = "http://127.1.34.1:-1";
    EXPECT_FALSE(settings.IsValid());

    settings.WebServerUrl = "http://127.1.34.1:8888";
    EXPECT_TRUE(settings.IsValid());
  }
}
}
