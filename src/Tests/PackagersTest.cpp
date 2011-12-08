#include <QDebug>
#include <QString>
#include <QVariant>

#include "DissentTest.hpp"
#include "Web/HttpResponse.hpp"
#include "Web/Packagers/JsonPackager.hpp"

namespace Dissent {
namespace Tests {

  namespace {
    using namespace Dissent::Web;
    using namespace Dissent::Web::Packagers;
  }

  TEST(Packager, Null)
  {
    QVariant var;
    HttpResponse resp;
    JsonPackager pack;
    ASSERT_TRUE(pack.Package(var, resp));

    QString data = resp.GetBody();
    ASSERT_EQ(QString("null\n"), data);
  }

  TEST(Packager, EmptyString)
  {
    QVariant var;
    var.setValue(QString(""));
    HttpResponse resp;
    JsonPackager pack;
    ASSERT_TRUE(pack.Package(var, resp));

    QString data = resp.GetBody();
    ASSERT_EQ(QString("\"\"\n"), resp.GetBody());
  }

  TEST(Packager, HelloString)
  {
    QVariant var;
    var.setValue(QString("Hello!"));
    HttpResponse resp;
    JsonPackager pack;
    ASSERT_TRUE(pack.Package(var, resp));

    QString data = resp.GetBody();
    ASSERT_EQ(QString("\"Hello!\"\n"), resp.GetBody());
  }

  TEST(Packager, List) 
  {
    QVariant var;
    HttpResponse resp;
    JsonPackager pack;

    QList<QVariant> list;
    list.append(QVariant("A"));
    list.append(QVariant("B"));
    list.append(QVariant("C"));

    var.setValue(list);
    ASSERT_TRUE(pack.Package(var, resp));

    QString data = resp.GetBody();
    ASSERT_EQ(QString("[ \"A\", \"B\", \"C\" ]\n"), resp.GetBody());
  }
}
}
