#include "DissentTest.hpp"
#include "RoundTest.hpp"
#include "BulkRoundHelpers.hpp"
#include "ShuffleRoundHelpers.hpp"

namespace Dissent {
namespace Tests {

  class BlogDropRoundTest : 
    public ::testing::TestWithParam<CryptoFactory::ThreadingType> {
  };

  TEST_P(BlogDropRoundTest, BasicManaged)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType tt = cf.GetThreadingType();
    cf.SetThreading(GetParam());

    RoundTest_Basic(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);

    cf.SetThreading(tt);
  }

  TEST_P(BlogDropRoundTest, MultiRoundManaged)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType tt = cf.GetThreadingType();
    cf.SetThreading(GetParam());

    RoundTest_MultiRound(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);

    cf.SetThreading(tt);
  }

  TEST_P(BlogDropRoundTest, AddOne)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType tt = cf.GetThreadingType();
    cf.SetThreading(GetParam());

    RoundTest_AddOne(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
    
    cf.SetThreading(tt);
  }

  TEST_P(BlogDropRoundTest, PeerDisconnectMiddleManaged)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType tt = cf.GetThreadingType();
    cf.SetThreading(GetParam());

    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
    
    cf.SetThreading(tt);
  }

  TEST_P(BlogDropRoundTest, PeerTransientIssueMiddle)
  {
    CryptoFactory &cf = CryptoFactory::GetInstance();
    CryptoFactory::ThreadingType tt = cf.GetThreadingType();
    cf.SetThreading(GetParam());

    RoundTest_PeerDisconnectMiddle(SessionCreator(TCreateBlogDropRound_Testing<BlogDropRound>),
        Group::ManagedSubgroup);
    
    cf.SetThreading(tt);
  }

  INSTANTIATE_TEST_CASE_P(BlogDropRound, BlogDropRoundTest,
      ::testing::Values(
        CryptoFactory::SingleThreaded,
        CryptoFactory::MultiThreaded));
}
}
