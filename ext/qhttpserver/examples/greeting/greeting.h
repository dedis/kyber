#include <QObject>

class QHttpRequest;
class QHttpResponse;

class Greeting : public QObject
{
    Q_OBJECT
public:
    Greeting();

private slots:
    void handle(QHttpRequest *req, QHttpResponse *resp);
};
