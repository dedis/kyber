
#include <QDebug>
#include <QString>

#include "BlameMatrix.hpp"

namespace Dissent {
namespace Anonymity {
namespace Tolerant {

  BlameMatrix::BlameMatrix(uint num_users, uint num_servers) :
    _num_users(num_users),
    _num_servers(num_servers),
    _user_output_bits(_num_users),
    _server_output_bits(_num_servers)
  {
    _data.resize(_num_users);
    for(uint user_idx=0; user_idx<_num_users; user_idx++) {
      _data[user_idx].resize(_num_servers);
    }
  }

  void BlameMatrix::AddUserAlibi(uint user_idx, const QBitArray &bits)
  {
    Q_ASSERT(user_idx < _num_users);
    Q_ASSERT(_num_servers == static_cast<uint>(bits.count()));

    for(uint server_idx=0; server_idx<_num_servers; server_idx++) {
      _data[user_idx][server_idx].user_bit = bits[server_idx];
    }
  }

  void BlameMatrix::AddServerAlibi(uint server_idx, const QBitArray &bits)
  {
    Q_ASSERT(server_idx < _num_servers);
    Q_ASSERT(_num_users == static_cast<uint>(bits.count()));

    for(uint user_idx=0; user_idx<_num_users; user_idx++) {
      _data[user_idx][server_idx].server_bit= bits[user_idx];
    }
  }

  void BlameMatrix::AddUserOutputBit(uint user_idx, bool bit) 
  {
    _user_output_bits.setBit(user_idx, bit);
  }

  void BlameMatrix::AddServerOutputBit(uint server_idx, bool bit)
  {
    _server_output_bits.setBit(server_idx, bit);
  }

  QVector<int> BlameMatrix::GetBadUsers() const
  {
    QVector<int> bad;
    for(uint user_idx=0; user_idx<_num_users; user_idx++) {
      bool out = false;
      QString debug;
      for(uint server_idx=0; server_idx<_num_servers; server_idx++) {
        out ^= _data[user_idx][server_idx].user_bit;
        debug += (QString("^") + (_data[user_idx][server_idx].user_bit ? "1" : "0"));
      }

      if(out != _user_output_bits[user_idx]) {
        bad.append(user_idx);
      }
      qDebug() << "BITS" << user_idx << ":" << _user_output_bits[user_idx] << " == " << debug;
    }
    return bad;
  }

  QVector<int> BlameMatrix::GetBadServers() const
  {
    QVector<int> bad;
    for(uint server_idx=0; server_idx<_num_servers; server_idx++) {
      bool out = false;

      QString debug;
      for(uint user_idx=0; user_idx<_num_users; user_idx++) {
        out ^= _data[user_idx][server_idx].server_bit;
        debug += (QString("^") + (_data[user_idx][server_idx].server_bit ? "1" : "0"));
      }

      if(out != _server_output_bits[server_idx]) {
        bad.append(server_idx);
      }
      qDebug() << "BITS" << server_idx << ":" << _server_output_bits[server_idx] << " == " << debug;
    }
    return bad;
  }

  QList<Conflict> BlameMatrix::GetConflicts(uint slot_idx) const
  {
    QList<Conflict> conflicts;
    for(uint user_idx=0; user_idx<_num_users; user_idx++) {
      for(uint server_idx=0; server_idx<_num_servers; server_idx++) {
        struct bit_pair bits = _data[user_idx][server_idx];
        if(bits.user_bit != bits.server_bit) {
          Conflict c(slot_idx, user_idx, bits.user_bit, server_idx, bits.server_bit);
          conflicts.append(c);
        }
      }
    }

    return conflicts;
  }

}
}
}

