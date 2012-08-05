#ifndef DISSENT_CRYPTO_KEY_SHARE_H_GUARD
#define DISSENT_CRYPTO_KEY_SHARE_H_GUARD

#include <QHash>
#include <QLinkedList>
#include <QSharedPointer>

#include "AsymmetricKey.hpp"
#include "CryptoFactory.hpp"
#include "Library.hpp"

namespace Dissent {
namespace Crypto {
  /**
   * Acts as a intermediary between AsymmetricKeys and a backend,
   * whether it be from memory or disk.
   * @todo use QFileSystemWatcher to allow users to dynamically add new keys
   */
  class KeyShare {
    public:
      /**
       * Initializes a new key share
       * @param path an optional file system path where keys might reside
       */
      explicit KeyShare(const QString &path = QString());

      /**
       * Returns the list of names for the keys stored herein
       */
      inline QList<QString> GetNames() const { return _keys.keys(); }

      /**
       * Returns the key under the given name an empty key if no such
       * name exists.
       */
      QSharedPointer<AsymmetricKey> GetKey(const QString &name) const;

      /**
       * Add a key to the share
       * @param name the name of the key
       * @param key the AsymmetricKey key
       * @todo should save to disk if _fs_enabled is true
       */
      void AddKey(const QString &name, QSharedPointer<AsymmetricKey> key);

      /**
       * Returns true of the named key exists
       */
      bool Contains(const QString &name) const;

      /**
       * An iterator class for KeyShare, enables iterating the keys
       * by order of their name
       */
      class const_iterator {
        public:
          typedef std::output_iterator_tag iterator_category;
          typedef QSharedPointer<AsymmetricKey> value_type;
          typedef const QSharedPointer<AsymmetricKey> *pointer;
          typedef const QSharedPointer<AsymmetricKey> &reference;

          inline const_iterator(const KeyShare *keyshare, bool end = false) :
            _keys(keyshare->_keys),
            _iterator(end ? keyshare->_sorted_keys.end() :
                keyshare->_sorted_keys.begin())
          {
          }

          inline const_iterator(const const_iterator &it) :
            _keys(it._keys),
            _iterator(it._iterator)
          {}

          inline const_iterator &operator=(const const_iterator &it)
          {
            _keys = it._keys;
            _iterator = it._iterator;
            return *this;
          }

          inline QSharedPointer<AsymmetricKey> operator*() const
          {
            return _keys.value(*_iterator);
          }

          inline bool operator==(const const_iterator &it) const
          {
            return (_keys == it._keys) &&
              (_iterator == it._iterator);
          }

          inline bool operator!=(const const_iterator &it) const
          {
            return !this->operator==(it);
          }

          inline const_iterator &operator++()
          {
            _iterator++;
            return *this;
          }

        private:
          QHash<QString, QSharedPointer<AsymmetricKey> > _keys;
          QLinkedList<QString>::const_iterator _iterator;
      };

      inline const_iterator begin() const { return const_iterator(this); }
      inline const_iterator end() const { return const_iterator(this, true); }


    private:
      void CheckPath();

      bool _fs_enabled;
      QString _path;

      QLinkedList<QString> _sorted_keys;
      QHash<QString, QSharedPointer<AsymmetricKey> > _keys;
  };
}
}

#endif
