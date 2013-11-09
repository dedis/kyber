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
    EXPECT_EQ(settings.RemoteEndPoints.count(), 0);
    settings.Auth = false;
    settings.LocalEndPoints.append(
        AddressFactory::GetInstance().CreateAddress("buffer://5"));
    settings.RemoteEndPoints.append(
      AddressFactory::GetInstance().CreateAddress("buffer://6"));
    settings.LocalId = QList<Id>();
    settings.LocalId.append(id);
    settings.Save();

    Settings settings0("dissent.ini", false);
    settings0.Auth = false;
    EXPECT_EQ(settings0.LocalEndPoints.count(), 1);
    EXPECT_EQ(settings0.RemoteEndPoints.count(), 1);

    EXPECT_EQ(settings0.LocalEndPoints[0],
        AddressFactory::GetInstance().CreateAddress("buffer://5"));

    EXPECT_EQ(settings0.RemoteEndPoints[0],
        AddressFactory::GetInstance().CreateAddress("buffer://6"));

    settings0.LocalEndPoints.append(
        AddressFactory::GetInstance().CreateAddress("buffer://7"));

    settings0.RemoteEndPoints.append(
        AddressFactory::GetInstance().CreateAddress("buffer://8"));

    settings0.Save();

    QStringList settings_list0;
    settings_list0 << "dissent" << "dissent.ini";
    Settings settings1 = Settings::CommandLineParse(settings_list0, false);
    settings1.Auth = false;
    EXPECT_EQ(settings1.LocalEndPoints.count(), 2);
    EXPECT_EQ(settings1.RemoteEndPoints.count(), 2);

    EXPECT_EQ(settings1.LocalEndPoints[0],
        AddressFactory::GetInstance().CreateAddress("buffer://5"));

    EXPECT_EQ(settings1.LocalEndPoints[1],
        AddressFactory::GetInstance().CreateAddress("buffer://7"));

    EXPECT_EQ(settings1.RemoteEndPoints[0],
        AddressFactory::GetInstance().CreateAddress("buffer://6"));

    EXPECT_EQ(settings1.RemoteEndPoints[1],
        AddressFactory::GetInstance().CreateAddress("buffer://8"));

    EXPECT_EQ(id, settings1.LocalId[0]);

    QStringList settings_list;
    settings_list << "application" << "--remote_endpoints" << "buffer://5" <<
      "--remote_endpoints" << "buffer://6" <<
      "--local_endpoints" << "buffer://4" << "--local_nodes" << "3" <<
      "--auth_mode" << "null" << "--session_type" << "csbulk" <<
      "--log" << "stderr" << "--console" <<
      "--web_server_url" << "http://127.0.0.1:8000" <<
      "--entry_tunnel_url" << "tcp://127.0.0.1:8081" <<
      "--exit_tunnel" << "--multithreading" <<
      "--local_id" << "'HJf+qfK7oZVR3dOqeUQcM8TGeVA='" <<
      "--server_ids" << "'HJf+qfK7oZVR3dOqeUQcM8TGeVA='";

    Settings settings2 = Settings::CommandLineParse(settings_list, false);
    settings2.Auth = false;

    EXPECT_EQ(settings2.LocalEndPoints.count(), 1);
    EXPECT_EQ(settings2.LocalEndPoints[0],
        AddressFactory::GetInstance().CreateAddress("buffer://4"));

    EXPECT_EQ(settings2.RemoteEndPoints.count(), 2);
    EXPECT_EQ(settings2.RemoteEndPoints[0],
        AddressFactory::GetInstance().CreateAddress("buffer://5"));

    EXPECT_EQ(settings2.RemoteEndPoints[1],
        AddressFactory::GetInstance().CreateAddress("buffer://6"));

    EXPECT_EQ(settings2.LocalNodeCount, 3);
//    EXPECT_EQ(settings2.SessionType, SessionFactory::CSBULK);
    EXPECT_EQ(settings2.Log, "stderr");
    EXPECT_TRUE(settings2.Console);
    EXPECT_EQ(settings2.WebServerUrl, QUrl("http://127.0.0.1:8000"));
    EXPECT_TRUE(settings2.WebServer);
    EXPECT_EQ(settings2.EntryTunnelUrl, QUrl("tcp://127.0.0.1:8081"));
    EXPECT_TRUE(settings2.EntryTunnel);
    EXPECT_TRUE(settings2.ExitTunnel);
    EXPECT_TRUE(settings2.Multithreading);
  }

  TEST(Settings, Invalid)
  {
    Settings settings;
    settings.Auth = false;
    EXPECT_FALSE(settings.IsValid());

    settings.LocalEndPoints.append(
        AddressFactory::GetInstance().CreateAddress("buffer://5"));
    EXPECT_FALSE(settings.IsValid());

    settings.ServerIds = QList<Id>();
    settings.ServerIds.append(Id());
    EXPECT_TRUE(settings.IsValid());
  }

  TEST(Settings, WebServer)
  {
    Settings settings;
    settings.Auth = false;
    settings.LocalEndPoints.append(
        AddressFactory::GetInstance().CreateAddress("buffer://5"));
    settings.ServerIds = QList<Id>();
    settings.ServerIds.append(Id());
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
