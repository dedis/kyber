#include <QObject>

class QHttpRequest;
class QHttpResponse;

class Hello : public QObject
{
    Q_OBJECT
public:
    Hello();

private slots:
    void handle(QHttpRequest *req, QHttpResponse *resp);
};
