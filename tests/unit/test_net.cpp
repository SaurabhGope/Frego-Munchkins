#include <array>

#include <catch2/catch_test_macros.hpp>

#include "frego/net/bytes.hpp"
#include "frego/net/ipv4.hpp"
#include "frego/net/mac.hpp"
#include "frego/net/oui.hpp"
#include "frego/net/sha256.hpp"

using namespace frego::net;

TEST_CASE("ByteReader reads big-endian fields and latches failure", "[net]") {
    const std::array<std::uint8_t, 7> buf{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    ByteReader r(buf);
    CHECK(r.u8() == 0x01);
    CHECK(r.u16be() == 0x0203);
    CHECK(r.u32be() == 0x04050607);
    CHECK_FALSE(r.failed());
    CHECK(r.u8() == 0);  // past the end
    CHECK(r.failed());
    CHECK(r.remaining() == 0);
}

TEST_CASE("ByteReader sub-readers inherit failure", "[net]") {
    const std::array<std::uint8_t, 3> buf{0x02, 0xAA, 0xBB};
    ByteReader r(buf);
    auto len = r.u8();
    auto child = r.sub(len);
    CHECK(child.u16be() == 0xAABB);
    CHECK_FALSE(child.failed());
    auto overrun = r.sub(5);
    CHECK(overrun.failed());
    CHECK(r.failed());
}

TEST_CASE("Mac parses macOS unpadded output and canonicalises", "[net]") {
    auto mac = Mac::parse("b4:3d:8:2:98:e8");
    REQUIRE(mac);
    CHECK(mac->str() == "b4:3d:08:02:98:e8");
    CHECK(Mac::parse("B4-3D-08-02-98-E8")->str() == "b4:3d:08:02:98:e8");
    CHECK_FALSE(Mac::parse("b4:3d:08:02:98"));
    CHECK_FALSE(Mac::parse("b4:3d:08:02:98:e8:00"));
    CHECK_FALSE(Mac::parse("b4:3d:008:02:98:e8"));
    CHECK_FALSE(Mac::parse("zz:3d:08:02:98:e8"));
    CHECK_FALSE(Mac::parse(""));
}

TEST_CASE("Mac flags randomized, multicast and OUI", "[net]") {
    // Values from the builder's network: the extender's rewritten MAC and a private iPhone MAC.
    CHECK(Mac::parse("22:23:51:01:2a:2b")->locally_administered());
    CHECK(Mac::parse("d6:3f:25:96:09:da")->locally_administered());
    CHECK_FALSE(Mac::parse("80:8a:bd:f1:db:d2")->locally_administered());
    CHECK(Mac::parse("01:00:5e:00:00:fb")->multicast());
    CHECK(Mac::parse("80:8a:bd:f1:db:d2")->oui() == 0x808ABD);
}

TEST_CASE("OuiDb parses IEEE CSV with quoted fields", "[net]") {
    auto db = OuiDb::parse_csv(
        "Registry,Assignment,Organization Name,Organization Address\n"
        "MA-L,808ABD,\"Samsung Electronics Co.,Ltd\",\"Suwon, KR\"\r\n"
        "MA-L,B43D08,\"Acme \"\"Routers\"\" Inc.\",\"1 Main St\nSpringfield\"\n"
        "MA-M,ABCDEF,Not MA-L,x\n"
        "MA-L,XYZ123,Bad hex,x\n");
    CHECK(db.size() == 2);
    CHECK(db.lookup(*Mac::parse("80:8a:bd:f1:db:d2")) == "Samsung Electronics Co.,Ltd");
    CHECK(db.lookup(*Mac::parse("b4:3d:08:02:98:e8")) == "Acme \"Routers\" Inc.");
    CHECK_FALSE(db.lookup(*Mac::parse("22:23:51:01:2a:2b")));  // locally administered: never a vendor
}

TEST_CASE("Ipv4 parse/format and subnet math", "[net]") {
    auto ip = Ipv4::parse("192.168.1.27");
    REQUIRE(ip);
    CHECK(ip->str() == "192.168.1.27");
    CHECK_FALSE(Ipv4::parse("192.168.1"));
    CHECK_FALSE(Ipv4::parse("192.168.1.256"));
    CHECK_FALSE(Ipv4::parse("192.168.01.1"));
    CHECK_FALSE(Ipv4::parse("192.168.1.1 "));
    CHECK(Ipv4::parse("224.0.0.251")->multicast());

    auto s = Subnet::of(*ip, *Ipv4::parse("255.255.255.0"));
    CHECK(s.str() == "192.168.1.0/24");
    CHECK(s.broadcast().str() == "192.168.1.255");
    CHECK(s.host_count() == 254);
    CHECK(s.contains(*Ipv4::parse("192.168.1.1")));
    CHECK_FALSE(s.contains(*Ipv4::parse("192.168.2.1")));
}

TEST_CASE("Sha256 matches FIPS 180-4 vectors", "[net]") {
    CHECK(Sha256::hex("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(Sha256::hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(Sha256::hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    Sha256 h;  // one million 'a', fed in uneven chunks
    std::string chunk(997, 'a');
    std::size_t left = 1'000'000;
    while (left) {
        auto n = std::min(left, chunk.size());
        h.update(std::string_view(chunk).substr(0, n));
        left -= n;
    }
    std::string hex;
    for (auto b : h.finish()) hex += std::format("{:02x}", b);
    CHECK(hex == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}
