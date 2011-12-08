#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  TEST(Settings, Basic)
  {
    Id id;
    QFile file("dissent.ini");
    file.remove();

    Settings settings("dissent.ini");
    EXPECT_EQ(settings.LocalEndPoints.count(), 0);
    EXPECT_EQ(settings.RemotePeers.count(), 0);
    settings.LocalEndPoints.append(QUrl("buffer://5"));
    settings.RemotePeers.append(QUrl("buffer://6"));
    settings.LocalId = id.ToString();
    settings.Save();

    Settings settings0("dissent.ini");
    EXPECT_EQ(settings0.LocalEndPoints.count(), 1);
    EXPECT_EQ(settings0.RemotePeers.count(), 1);
    EXPECT_EQ(settings0.LocalEndPoints[0], QUrl("buffer://5"));
    EXPECT_EQ(settings0.RemotePeers[0], QUrl("buffer://6"));
    settings0.LocalEndPoints.append(QUrl("buffer://7"));
    settings0.RemotePeers.append(QUrl("buffer://8"));
    settings0.Save();

    Settings settings1("dissent.ini");
    EXPECT_EQ(settings0.LocalEndPoints.count(), 2);
    EXPECT_EQ(settings0.RemotePeers.count(), 2);
    EXPECT_EQ(settings0.LocalEndPoints[0], QUrl("buffer://5"));
    EXPECT_EQ(settings0.LocalEndPoints[1], QUrl("buffer://7"));
    EXPECT_EQ(settings0.RemotePeers[0], QUrl("buffer://6"));
    EXPECT_EQ(settings0.RemotePeers[1], QUrl("buffer://8"));
    EXPECT_EQ(id, Id(settings1.LocalId));
  }

  TEST(Settings, HostAddress)
  {
    Settings settings;

    settings.LocalEndPoints.append(QUrl("buffer://5"));
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
