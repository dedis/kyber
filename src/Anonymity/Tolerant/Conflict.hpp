#ifndef DISSENT_ANONYMITY_TOLERANT_CONFLICT_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_CONFLICT_H_GUARD

#include <QString>

namespace Dissent {
namespace Anonymity {
namespace Tolerant {
  
  class Conflict {

    public:
      Conflict(uint slot_idx,
          uint user_idx, bool user_bit,
          uint server_idx, bool server_bit) :
        _slot_idx(slot_idx),
        _user_idx(user_idx),
        _user_bit(user_bit),
        _server_idx(server_idx),
        _server_bit(server_bit) {}

      inline uint GetSlotIndex() const { return _slot_idx; }

      inline uint GetUserIndex() const { return _user_idx; }

      inline bool GetUserBit() const { return _user_bit; }

      inline uint GetServerIndex() const { return _server_idx; }

      inline bool GetServerBit() const { return _server_bit; }

    private:
    
      uint _slot_idx;

      uint _user_idx;
      bool _user_bit;

      uint _server_idx;
      bool _server_bit;

  };
}
} 
}

#endif
