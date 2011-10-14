#include "SecureSession.hpp"

namespace Dissent {
namespace Anonymity {
  SecureSession::SecureSession(const Id &local_id, const Id &leader_id,
      const Group &group, ConnectionTable &ct, RpcHandler &rpc,
      const Id &session_id, AsymmetricKey *signing_key,
      CreateSecureRound create_round, const QByteArray &default_data) :
    Session(local_id, leader_id, group, ct, rpc, session_id, 0, default_data),
    _signing_key(signing_key),
    _create_secure_round(create_round)
  {
  }

  Round *SecureSession::GetRound(const QByteArray &data)
  {
    return _create_secure_round(_local_id, _group, _ct, _rpc, _session_id,
        _signing_key, data);
  }
}
}
