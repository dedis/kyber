#include <QDataStream>

#include "CppDsaPrivateKey.hpp"
#include "CppDsaPublicKey.hpp"
#include "CppHash.hpp"
#include "CppNeffShuffle.hpp"
#include "CppRandom.hpp"

namespace Dissent {
namespace Crypto {
  bool CppNeffShuffle::Shuffle(const QVector<QByteArray> &input,
      const QSharedPointer<AsymmetricKey> &private_key,
      const QVector<QSharedPointer<AsymmetricKey> > &remaining_keys,
      QVector<QByteArray> &output,
      QByteArray &proof)
  {
    QSharedPointer<CppDsaPrivateKey> pkey = private_key.dynamicCast<CppDsaPrivateKey>();
    if(!pkey) {
      qCritical() << "Unable to convert pkey to DSA key";
      return false;
    }

    // Setup
    int k = input.size();
    QVector<Integer> X, Y;
    for(int idx = 0; idx < input.size(); idx++) {
      QDataStream tstream(input[idx]);
      Integer shared, enc;
      tstream >> shared >> enc;
      X.append(shared);
      Y.append(enc);
    }

    Integer modulus = pkey->GetModulus();
    Integer subgroup = pkey->GetSubgroup();
    Integer generator = pkey->GetGenerator();
    Integer h = pkey->GetPublicElement();

    foreach(const QSharedPointer<AsymmetricKey> &key, remaining_keys) {
      QSharedPointer<CppDsaPublicKey> tkey = key.dynamicCast<CppDsaPublicKey>();
      if(!tkey) {
        qCritical() << "Unable to convert pkey to DSA key";
        return false;
      }

      h = (h * tkey->GetPublicElement()) % modulus;
    }

    // Non-interactive setup
    proof.clear();
    QDataStream stream(&proof, QIODevice::WriteOnly);
    CppHash hash;
    foreach(const QByteArray &in, input) {
      hash.Update(in);
    }
    QByteArray base_seed = hash.ComputeHash();
    QByteArray cseed;
    CppRandom rand;

    // Reencryption betas
    QVector<Integer> beta;
    for(int idx = 0; idx < k; idx++) {
      beta.append(Integer::GetRandomInteger(2, subgroup));
    }

    // Rencryption
    QVector<Integer> X_bar, Y_bar;
    QVector<QPair<QByteArray, int> > sortable;
    
    for(int idx = 0; idx < k; idx++) {
      Integer X_bar_l = (X[idx] *
          generator.Pow(beta[idx], modulus)) % modulus;
      X_bar.append(X_bar_l);

      Integer Y_bar_l = (Y[idx] *
          h.Pow(beta[idx], modulus)) % modulus;
      Y_bar.append(Y_bar_l);

      QByteArray toutput;
      QDataStream tstream(&toutput, QIODevice::WriteOnly);
      tstream << X_bar_l << Y_bar_l;
      sortable.append(QPair<QByteArray, int>(toutput, idx));
    }

    // Mixxing
    qSort(sortable);
    QVector<Integer> X_bar_tmp, Y_bar_tmp;

    QVector<int> pi(k), inv_pi(k);
    output.clear();
    for(int idx = 0; idx < k; idx++) {
      pi[idx] = sortable[idx].second;
      inv_pi[sortable[idx].second] = idx;

      X_bar_tmp.append(X_bar[pi[idx]]);
      Y_bar_tmp.append(Y_bar[pi[idx]]);
      output.append(sortable[idx].first);
    }

    X_bar = X_bar_tmp;
    Y_bar = Y_bar_tmp;

    // Part 0 -- Generation of secrets

    QVector<Integer> u, w, a;
    for(int idx = 0; idx < k; idx++) {
      u.append(Integer::GetRandomInteger(2, subgroup));
      w.append(Integer::GetRandomInteger(2, subgroup));
      a.append(Integer::GetRandomInteger(2, subgroup));
    }

    Integer gamma = Integer::GetRandomInteger(2, subgroup);
    Integer tau_0 = Integer::GetRandomInteger(2, subgroup);

    // Part 1 -- Generation of initial shares

    Integer Gamma = generator.Pow(gamma, modulus);
    QVector<Integer> A, C, U, W;
    for(int idx = 0; idx < k; idx++) {
      A.append(generator.Pow(a[idx], modulus));
      U.append(generator.Pow(u[idx], modulus));
      W.append(generator.Pow((gamma * w[idx]) % subgroup, modulus));
    }

    for(int idx = 0; idx < k; idx++) {
      C.append(A[pi[idx]].Pow(gamma, modulus));
    }

    Integer delta_sum = tau_0, x_multi = 1, y_multi = 1;
    for(int idx = 0; idx < k; idx++) {
      delta_sum = (delta_sum + w[idx] * beta[pi[idx]]) % subgroup;
      x_multi = (x_multi * X[idx].Pow((w[inv_pi[idx]] - u[idx]) % subgroup, modulus)) % modulus;
      y_multi = (y_multi * Y[idx].Pow((w[inv_pi[idx]] - u[idx]) % subgroup, modulus)) % modulus;
    }
    Integer Delta_0 = (generator.Pow(delta_sum, modulus) * x_multi) % modulus;
    Integer Delta_1 = (h.Pow(delta_sum, modulus) * y_multi) % modulus;

    stream << output << Gamma << A << C << U << W << Delta_0 << Delta_1;

    // Part 2 -- Non-Interactive Verifier
    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    QVector<Integer> p, B;
    for(int idx = 0; idx < k; idx++) {
      p.append(rand.GetInteger(2, subgroup));
      B.append((generator.Pow(p[idx], modulus) *
            U[idx].MultiplicativeInverse(modulus)) % modulus);
    }

    // Part 3 -- Prover

    QVector<Integer> b, d, D;
    for(int idx = 0; idx < k; idx++) {
      b.append((p[idx] - u[idx]) % subgroup);
    }

    for(int idx = 0; idx < k; idx++) {
      d.append((gamma * b[pi[idx]]) % subgroup);
      D.append(generator.Pow(d[idx], modulus));
    }

    stream << D;

    // Part 4 -- Verifier

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    Integer lambda = rand.GetInteger(2, subgroup);

    // Part 5 -- Prover

    QVector<Integer> r, s, sigma;
    Integer tau = subgroup - tau_0;

    for(int idx = 0; idx < k; idx++) {
      r.append((a[idx] + lambda * b[idx]) % subgroup);
    }

    for(int idx = 0; idx < k; idx++) {
      s.append((gamma * r[pi[idx]]) % subgroup);
      sigma.append((w[idx] + b[pi[idx]]) % subgroup);
      tau = (tau + b[idx] * beta[idx]) % subgroup;
    }

    stream << tau << sigma;
    // Part 6 -- SimpleKShuffle (R, S, G, Gamma)

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    // Part 6.1 - Verifier Challenger

    Integer t = rand.GetInteger(2, subgroup);

    // Part 6.2

    QVector<Integer> r_t, s_t;

    for(int idx = 0; idx < k; idx++) {
      r_t.append((r[idx] - t) % subgroup);
      s_t.append((s[idx] - (gamma * t)) % subgroup);
    }

    QVector<Integer> theta;

    for(int idx = 0; idx < (2 * k) - 1; idx++) {
      theta.append(Integer::GetRandomInteger(0, subgroup));
    }

    QVector<Integer> Theta;
    Theta.append(generator.Pow(subgroup - (theta[0] * s_t[0]) % subgroup, modulus));
    for(int idx = 1; idx < k; idx++) {
      Theta.append(generator.Pow((theta[idx - 1] * r_t[idx] - theta[idx] * s_t[idx]) % subgroup, modulus));
    }

    for(int idx = k; idx < (2 * k - 1); idx++) {
      Theta.append(generator.Pow((gamma * theta[idx - 1] - theta[idx]) % subgroup, modulus));
    }

    Theta.append(generator.Pow((gamma * theta[2 * k - 2]) % subgroup, modulus));

    stream << Theta;

    // Part 6.3 - Verifier

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    Integer c = rand.GetInteger(2, subgroup);

    // Part 6.4 - Prover

    QVector<Integer> alpha;

    Integer s_r_multi = c;
    for(int idx = 0 ; idx <  k; idx++) {
      s_r_multi = (s_r_multi * r_t[idx] * s_t[idx].MultiplicativeInverse(subgroup)) % subgroup;
      alpha.append((theta[idx] + s_r_multi) % subgroup);
    }

    Integer inv_gamma = gamma.MultiplicativeInverse(subgroup);
    for(int idx = k; idx < (2 * k - 1); idx++) {
      alpha.append((theta[idx] + c * inv_gamma.Pow(2 * k - idx - 1, subgroup)) % subgroup);
    }

    stream << alpha;

    // Part 8 Verifiable decryption
    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    QVector<QByteArray> decrypted;
    QVector<QPair<Integer, Integer> > decryption_proof;

    foreach(const QByteArray &encrypted, output) {
      decrypted.append(pkey->SeriesDecrypt(encrypted));
      if(decrypted.last().isEmpty()) {
        qDebug() << "Invalid encryption";
        return false;
      }

      QDataStream tstream(encrypted);
      Integer shared;
      tstream >> shared;

      Integer t = Integer::GetRandomInteger(2, subgroup);
      Integer T = shared.Pow(t, modulus);
      Integer c = rand.GetInteger(2, subgroup);
      Integer s = (t + c * pkey->GetPrivateExponent()) % subgroup;
      decryption_proof.append(QPair<Integer, Integer>(T, s));
    }

    stream << decrypted;
    stream << decryption_proof;
    return true;
  }

  bool CppNeffShuffle::Verify(const QVector<QByteArray> &input,
      const QVector<QSharedPointer<AsymmetricKey> > &keys,
      const QByteArray &input_proof,
      QVector<QByteArray> &output)
  {
    if(keys.size() < 1) {
      qCritical() << "Needs at least 1 public key";
      return false;
    }

    QSharedPointer<CppDsaPublicKey> pkey =
      keys[0].dynamicCast<CppDsaPublicKey>();

    if(!pkey) {
      qCritical() << "Unable to convert pkey to DSA key";
      return false;
    }

    int k = input.size();
    Integer modulus = pkey->GetModulus();
    Integer subgroup = pkey->GetSubgroup();
    Integer generator = pkey->GetGenerator();
    Integer h = pkey->GetPublicElement();

    for(int idx = 1; idx < keys.size(); idx++) {
      QSharedPointer<CppDsaPublicKey> tkey =
        keys[idx].dynamicCast<CppDsaPublicKey>();

      if(!tkey) {
        qCritical() << "Unable to convert pkey to DSA key";
        return false;
      }

      h = (h * tkey->GetPublicElement()) % modulus;
    }

    QVector<Integer> X, Y;
    for(int idx = 0; idx < input.size(); idx++) {
      QDataStream tstream(input[idx]);
      Integer shared, enc;
      tstream >> shared >> enc;

      if(!pkey->InGroup(shared)) {
        qCritical() << "Shared" << idx << "not within group";
        return false;
      }
      if(!pkey->InGroup(enc)) {
        qCritical() << "Encrypted" << idx << "not within group";
        return false;
      }

      X.append(shared);
      Y.append(enc);
    }

    // Non-interactive setup
    QDataStream ostream(input_proof);
    QByteArray proof;
    QDataStream istream(&proof, QIODevice::WriteOnly);
    CppHash hash;
    foreach(const QByteArray &in, input) {
      hash.Update(in);
    }
    QByteArray base_seed = hash.ComputeHash();
    QByteArray cseed;
    CppRandom rand;

    // Part 1 -- Generation of initial shares

    QVector<QByteArray> shuffle_output;
    Integer Gamma;
    QVector<Integer> A, C, U, W;
    Integer Delta_0, Delta_1;

    ostream >> shuffle_output >> Gamma >> A >> C >> U >> W >> Delta_0 >> Delta_1;
    if(shuffle_output.size() != k) {
      qDebug() << "Output is incorrect length:" << shuffle_output.size();
      return false;
    }
    istream << shuffle_output << Gamma << A << C << U << W << Delta_0 << Delta_1;

    QVector<Integer> X_bar, Y_bar;
    for(int idx = 0; idx < input.size(); idx++) {
      if(idx > 0 && shuffle_output[idx - 1] > shuffle_output[idx]) {
        qDebug() << "Output is not sorted as expected";
        return false;
      }

      QDataStream tstream(shuffle_output[idx]);
      Integer shared, enc;
      tstream >> shared >> enc;
      X_bar.append(shared);
      Y_bar.append(enc);
    }

    // Part 2 -- Non-Interactive Verifier
    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    QVector<Integer> p, B;
    for(int idx = 0; idx < k; idx++) {
      p.append(rand.GetInteger(2, subgroup));
      B.append((generator.Pow(p[idx], modulus) *
            U[idx].MultiplicativeInverse(modulus)) % modulus);
    }

    // Part 3 -- Prover

    QVector<Integer> D;

    ostream >> D;
    istream << D;

    // Part 4 -- Verifier

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    Integer lambda = rand.GetInteger(2, subgroup);

    // Part 5 -- Prover

    Integer tau;
    QVector<Integer> sigma;

    ostream >> tau >> sigma;
    istream << tau << sigma;

    // Part 6 -- SimpleKShuffle (R, S, G, Gamma)

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    // Part 6.1 - Verifier Challenger

    Integer t = rand.GetInteger(2, subgroup);

    // Part 6.2

    QVector<Integer> Theta;

    ostream >> Theta;
    istream << Theta;

    if(Theta.size() != 2 * k) {
      qDebug() << "Invalid Theta size";
      return false;
    }

    // Part 6.3 - Verifier

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    Integer c = rand.GetInteger(2, subgroup);

    // Part 6.4 - Prover

    QVector<Integer> alpha;

    ostream >> alpha;
    istream << alpha;

    // Part 6.5 - Verifier

    QVector<Integer> R, S, R_t, S_t;
    Integer U_ = generator.Pow(subgroup - t, modulus);
    Integer W_ = Gamma.Pow(subgroup - t, modulus);

    for(int idx = 0; idx < k; idx++) {
      R.append((A[idx] * B[idx].Pow(lambda, modulus)) % modulus);
      R_t.append((R[idx] * U_) % modulus);

      S.append((C[idx] * D[idx].Pow(lambda, modulus)) % modulus);
      S_t.append((S[idx] * W_) % modulus);
    }

    if(Theta[0] !=
        ((R_t[0].Pow(c, modulus) *
         S_t[0].Pow(subgroup - alpha[0], modulus)) % modulus))
    {
      qDebug() << "Failed Theta[0] check";
      return false;
    }

    for(int idx = 1; idx < k; idx++) {
      if(Theta[idx] !=
          ((R_t[idx].Pow(alpha[idx - 1], modulus) *
            S_t[idx].Pow(subgroup - alpha[idx], modulus)) % modulus))
      {
        qDebug().nospace() << "Failed Theta[" << idx <<"] check";
        return false;
      }
    }

    for(int idx = k; idx < 2 * k - 1; idx++) {
      if(Theta[idx] !=
          ((Gamma.Pow(alpha[idx - 1], modulus) *
            generator.Pow(subgroup - alpha[idx], modulus)) % modulus))
      {
        qDebug().nospace() << "Failed Theta[" << idx <<"] check";
        return false;
      }
    }

    if(Theta[2 * k - 1] !=
        ((Gamma.Pow(alpha[2 * k - 2], modulus) *
          generator.Pow(subgroup - c, modulus)) % modulus))
    {
      qDebug().nospace() << "Failed Theta[" << (2 * k - 1) <<"] check";
      return false;
    }

    // Part 7 -- Verifier

    Integer iota_0 = 1, iota_1 = 1;
    for(int idx = 0; idx < k; idx++) {
      iota_0 = (iota_0 * X_bar[idx].Pow(sigma[idx], modulus) *
          X[idx].Pow(subgroup - p[idx], modulus)) % modulus;
      iota_1 = (iota_1 * Y_bar[idx].Pow(sigma[idx], modulus) *
          Y[idx].Pow(subgroup - p[idx], modulus)) % modulus;
      if(Gamma.Pow(sigma[idx], modulus) != ((W[idx] * D[idx]) % modulus)) {
        qDebug().nospace() << "Failed sigma[" << idx << "] check";
        return false;
      }
    }

    if(iota_0 != ((Delta_0 * generator.Pow(tau, modulus)) % modulus)) {
      qDebug() << "Failed Iota_0 check";
      return false;
    }

    if(iota_1 != ((Delta_1 * h.Pow(tau, modulus)) % modulus)) {
      qDebug() << "Failed Iota_1 check";
      return false;
    }


    // Part 8 -- Verifying Decryption
    QVector<QByteArray> decrypted;
    QVector<QPair<Integer, Integer> > decryption_proof;
    ostream >> decrypted >> decryption_proof;
    if(decrypted.size() != k) {
      qCritical() << "Decrypted size != k";
      return false;
    }

    if(decryption_proof.size() != k) {
      qCritical() << "Decryption proof size != k";
      return false;
    }

    hash.Update(base_seed);
    cseed = hash.ComputeHash(proof);
    rand = CppRandom(cseed);

    for(int idx = 0; idx < k; idx++) {
      QDataStream tstream_in(shuffle_output[idx]);
      Integer shared_in, secret_in;
      tstream_in >> shared_in >> secret_in;

      QDataStream tstream_out(decrypted[idx]);
      Integer shared_out, secret_out;
      tstream_out >> shared_out >> secret_out;

      Integer pair = (secret_in * secret_out.MultiplicativeInverse(modulus)) % modulus;
      Integer T = decryption_proof[idx].first;
      Integer s = decryption_proof[idx].second;
      Integer c = rand.GetInteger(2, subgroup);
      if(shared_in != shared_out) {
        qDebug() << "Decryption error";
        return false;
      }

      if(shared_out.Pow(s, modulus) != ((T * pair.Pow(c, modulus)) % modulus)) {
        qDebug() << "Invalid decryption proof";
        return false;
      }
    }

    output = decrypted;
    return true;
  }
}
}
