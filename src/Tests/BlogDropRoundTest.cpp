#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  class BadBlogDropRound : public BlogDropRound, public Triggerable {
    public:
      explicit BadBlogDropRound(const QSharedPointer<Parameters> &params,
          const Group &group, const PrivateIdentity &ident,
          const Id &round_id, const QSharedPointer<Network> &network,
          GetDataCallback &get_data, CreateRound create_shuffle,
          bool verify_proofs) :
        BlogDropRound(params, group, ident, round_id, network, get_data, create_shuffle, verify_proofs)
      {
      }

      virtual QString ToString() const
      {
        return BlogDropRound::ToString() + " BAD!";
      }

      virtual bool BadClient() const
      {
        qDebug() << "Bad client called";
        const_cast<BadBlogDropRound *>(this)->Triggerable::SetTriggered();
        return true;
      }
  };

  template <Crypto::BlogDrop::Parameters::ParameterType TYPE, typename SHUFFLE, bool VERIFY>
    QSharedPointer<Round> TCreateBadBlogDropRound(
      const Round::Group &group, const Round::PrivateIdentity &ident,
      const Connections::Id &round_id,
      QSharedPointer<Connections::Network> network,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<Round> round(new BadBlogDropRound(
          Crypto::BlogDrop::Parameters::GetParameters(TYPE, round_id.GetByteArray()),
          group, ident, round_id, network, get_data, &TCreateRound<SHUFFLE>, VERIFY));
    round->SetSharedPointer(round);
    return round;
  }

  TEST(BlogDropRoundTest, BasicManagedReactive)
  {
    RoundTest_Basic(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, BasicManagedProactive)
  {
    RoundTest_Basic(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, true>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, MultiRoundManaged)
  {
    RoundTest_MultiRound(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, AddOne)
  {
    RoundTest_AddOne(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, PeerDisconnectMiddleManaged)
  {
    RoundTest_PeerDisconnectMiddle(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, PeerTransientIssueMiddle)
  {
    RoundTest_PeerDisconnectMiddle(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        Group::ManagedSubgroup);
  }

  TEST(BlogDropRoundTest, BadClientReactive)
  {
    RoundTest_BadGuy(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        SessionCreator(TCreateBadBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, false>),
        Group::ManagedSubgroup, TBadGuyCB<BadBlogDropRound>);
  }

  TEST(BlogDropRoundTest, BadClientProactive)
  {
    RoundTest_BadGuy(
        SessionCreator(TCreateBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, true>),
        SessionCreator(TCreateBadBlogDropRound<
          Parameters::ParameterType_CppECHashingProduction, NullRound, true>),
        Group::ManagedSubgroup, TBadGuyCB<BadBlogDropRound>);
  }
}
}
