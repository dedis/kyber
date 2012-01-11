
#include <QDebug>

#include "MessageHistory.hpp"

namespace Dissent {
namespace Anonymity {
namespace Tolerant {
  
  MessageHistory::MessageHistory(uint num_users, uint num_servers) :
    _corrupted_slots(num_users, false),
    _user_data(num_users),
    _server_data(num_users),
    _num_users(num_users),
    _num_servers(num_servers) {}

  void MessageHistory::AddUserMessage(uint phase, uint slot, uint member, const QByteArray &message)
  {
    if(_user_data[slot][phase].isEmpty()) {
      _user_data[slot][phase].resize(_num_users);
    }

    //qDebug() << "User message phase" << phase << "slot" << slot << "user" << member;
    _user_data[slot][phase][member] = message;
  }

  void MessageHistory::AddServerMessage(uint phase, uint slot, uint member, const QByteArray &message) {
    if(_server_data[slot][phase].isEmpty()) {
      _server_data[slot][phase].resize(_num_servers);
    }

    //qDebug() << "Server message phase" << phase << "slot" << slot << "server" << member;
    _server_data[slot][phase][member] = message;
  }

  bool MessageHistory::GetUserOutputBit(uint slot, uint user_idx, const Accusation &acc) const
  {
    return (_user_data[slot][acc.GetPhase()][user_idx][acc.GetByteIndex()] & (1 << acc.GetBitIndex()));
  }

  bool MessageHistory::GetServerOutputBit(uint slot, uint server_idx, const Accusation &acc) const
  {
    return (_server_data[slot][acc.GetPhase()][server_idx][acc.GetByteIndex()] & (1 << acc.GetBitIndex()));
  }

  void MessageHistory::NextPhase() 
  {
    for(uint i=0; i<_num_users; i++) {
      if(!_corrupted_slots[i]) {
        _user_data[i].clear();
      }
    }

    for(uint i=0; i<_num_servers; i++) {
      if(!_corrupted_slots[i]) {
        _server_data[i].clear();
      }
    }
  }

  void MessageHistory::MarkSlotCorrupted(uint slot)
  {
    _corrupted_slots[slot] = true;
  }

  void MessageHistory::MarkSlotBlameFinished(uint slot)
  {
    _corrupted_slots[slot] = false;
  }

}
}
}
