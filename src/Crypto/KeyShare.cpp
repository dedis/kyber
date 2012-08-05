#include <QDir>
#include <QFile>

#include "KeyShare.hpp"

namespace Dissent {
namespace Crypto {
  KeyShare::KeyShare(const QString &path) :
    _fs_enabled(!path.isEmpty()),
    _path(path)
  {
    if(_fs_enabled) {
      CheckPath();
    }
  }

  QSharedPointer<AsymmetricKey> KeyShare::GetKey(const QString &name) const
  {
    if(_keys.contains(name)) {
      return _keys[name];
    } else if(_fs_enabled) {
      QString key_path = _path + "/" + name + ".pub";
      QFile key_file(key_path);
      if(key_file.exists()) {
        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        QSharedPointer<AsymmetricKey> key(lib->LoadPublicKeyFromFile(key_path));
        KeyShare *ks = const_cast<KeyShare *>(this);
        ks->_keys[name] = key;
        return key;
      }
    }

    return QSharedPointer<AsymmetricKey>();
  }

  void KeyShare::AddKey(const QString &name, QSharedPointer<AsymmetricKey> key)
  {
    _keys[name] = key;

    QMutableLinkedListIterator<QString> iterator(_sorted_keys);
    while(iterator.hasNext()) {
      if(name < iterator.peekNext()) {
        break;
      }
      iterator.next();
    }
    iterator.insert(name);
  }

  bool KeyShare::Contains(const QString &name) const
  {
    if(_keys.contains(name)) {
      return true;
    } else if(_fs_enabled) {
      QString key_path = _path + "/" + name + ".pub";
      QFile key_file(key_path);
      return key_file.exists();
    }

    return false;
  }

  void KeyShare::CheckPath()
  {
    Library *lib = CryptoFactory::GetInstance().GetLibrary();

    QDir key_path(_path, "*.pub");
    foreach(const QString &key_name, key_path.entryList()) {
      QString path = _path + "/" + key_name;
      QSharedPointer<AsymmetricKey> key(lib->LoadPublicKeyFromFile(path));
      if(!key->IsValid()) {
        qDebug() << "Invalid key:" << path;
        continue;
      }

      QString name = key_name.left(key_name.length() - 4);
      AddKey(name, key);
    }
  }
}
}
