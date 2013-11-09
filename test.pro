include(dissent.pro)
TEMPLATE = app
TARGET = test
DEPENDPATH += ext/googletest/src \
              ext/googletest/include/gtest \
              ext/googletest/include/gtest/internal
INCLUDEPATH += src \
               ext/googletest \
               ext/googletest/include
#DEFINES += QT_NO_DEBUG_OUTPUT
#DEFINES += QT_NO_WARNING_OUTPUT
DEFINES += DISSENT_TEST

# Input
HEADERS += ext/googletest/include/gtest/gtest-death-test.h \
           ext/googletest/include/gtest/gtest-message.h \
           ext/googletest/include/gtest/gtest-param-test.h \
           ext/googletest/include/gtest/gtest-printers.h \
           ext/googletest/include/gtest/gtest-spi.h \
           ext/googletest/include/gtest/gtest-test-part.h \
           ext/googletest/include/gtest/gtest-typed-test.h \
           ext/googletest/include/gtest/gtest.h \
           ext/googletest/include/gtest/gtest_pred_impl.h \
           ext/googletest/include/gtest/gtest_prod.h \
           ext/googletest/include/gtest/internal/gtest-death-test-internal.h \
           ext/googletest/include/gtest/internal/gtest-filepath.h \
           ext/googletest/include/gtest/internal/gtest-internal.h \
           ext/googletest/include/gtest/internal/gtest-linked_ptr.h \
           ext/googletest/include/gtest/internal/gtest-param-util-generated.h \
           ext/googletest/include/gtest/internal/gtest-param-util.h \
           ext/googletest/include/gtest/internal/gtest-port.h \
           ext/googletest/include/gtest/internal/gtest-string.h \
           ext/googletest/include/gtest/internal/gtest-tuple.h \
           ext/googletest/include/gtest/internal/gtest-type-util.h \
           src/Tests/AbstractGroupHelpers.hpp \
           src/Tests/DissentTest.hpp \
           src/Tests/Mock.hpp \
           src/Tests/MockEdgeHandler.hpp \
           src/Tests/MockSender.hpp \
           src/Tests/MockSource.hpp \
           src/Tests/OverlayTest.hpp \
           src/Tests/RpcTest.hpp \
           src/Tests/SessionTest.hpp

SOURCES += ext/googletest/src/gtest-all.cc \
           src/Tests/AddressTest.cpp \
           src/Tests/Base64.cpp \
           src/Tests/BlogDropProof.cpp \
           src/Tests/BlogDropTest.cpp \
           src/Tests/BlogDropUtilsTest.cpp \
           src/Tests/ConnectionTest.cpp \
           src/Tests/Crypto.cpp \
           src/Tests/DsaCryptoTest.cpp \
           src/Tests/EdgeTest.cpp \
           src/Tests/HashTest.cpp \
           src/Tests/IdTest.cpp \
           src/Tests/IntegerTest.cpp \
           src/Tests/KeyShareTest.cpp \
           src/Tests/MainTest.cpp \
           src/Tests/OnionTest.cpp \
           src/Tests/OverlayTest.cpp \
           src/Tests/RandomTest.cpp \
           src/Tests/RoundTest.cpp \
           src/Tests/RpcTest.cpp \
           src/Tests/SerializationTest.cpp \
           src/Tests/SessionTest.cpp \
           src/Tests/SettingsTest.cpp \
           src/Tests/TimeTest.cpp \
           src/Tests/TripleTest.cpp
