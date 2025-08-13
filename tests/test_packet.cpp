#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "../src/resolver/packet_builder.h"
#include "../src/resolver/packet_parser.h"
#include "../src/resolver/utils.h"

using namespace dns_resolver;

class PacketTest : public ::testing::Test {
protected:
  void SetUp() override { builder_ = std::make_unique<PacketBuilder>(); }

  std::unique_ptr<PacketBuilder> builder_;
};

TEST_F(PacketTest, BuildSimpleQuery) {
  auto packet = builder_->set_id(0x1234)
                    .set_flags(false, 0, false, false, true, false, 0)
                    .add_question("example.com", RecordType::A, RecordClass::IN)
                    .build();

  ASSERT_GE(packet.size(), 12u);  // At least header size

  // Check header
  EXPECT_EQ(packet[0], 0x12);  // ID high byte
  EXPECT_EQ(packet[1], 0x34);  // ID low byte
  EXPECT_EQ(packet[2], 0x01);  // Flags high byte (RD=1)
  EXPECT_EQ(packet[3], 0x00);  // Flags low byte
  EXPECT_EQ(packet[4], 0x00);  // QDCOUNT high byte
  EXPECT_EQ(packet[5], 0x01);  // QDCOUNT low byte (1 question)
}

TEST_F(PacketTest, ParseSimpleResponse) {
  // Create a simple DNS response packet
  std::vector<uint8_t> response = {
      0x12, 0x34,  // ID
      0x81, 0x80,  // Flags (QR=1, RD=1, RA=1)
      0x00, 0x01,  // QDCOUNT
      0x00, 0x01,  // ANCOUNT
      0x00, 0x00,  // NSCOUNT
      0x00, 0x00,  // ARCOUNT
      // Question: example.com A IN
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
      0x00,        // End of name
      0x00, 0x01,  // Type A
      0x00, 0x01,  // Class IN
      // Answer: example.com A IN 300 93.184.216.34
      0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm',
      0x00,                    // End of name
      0x00, 0x01,              // Type A
      0x00, 0x01,              // Class IN
      0x00, 0x00, 0x01, 0x2c,  // TTL (300)
      0x00, 0x04,              // RDLENGTH (4)
      93, 184, 216, 34         // IP address
  };

  PacketParser parser(response);
  EXPECT_TRUE(parser.is_valid_packet());

  auto message = parser.parse();

  EXPECT_EQ(message.header.id, 0x1234);
  EXPECT_TRUE(message.header.is_response());
  EXPECT_TRUE(message.header.recursion_available());
  EXPECT_EQ(message.header.qdcount, 1);
  EXPECT_EQ(message.header.ancount, 1);

  ASSERT_EQ(message.questions.size(), 1u);
  EXPECT_EQ(message.questions[0].qname, "example.com");
  EXPECT_EQ(message.questions[0].qtype, RecordType::A);

  ASSERT_EQ(message.answers.size(), 1u);
  EXPECT_EQ(message.answers[0].name, "example.com");
  EXPECT_EQ(message.answers[0].type, RecordType::A);
  EXPECT_EQ(message.answers[0].ttl, 300u);
}

TEST_F(PacketTest, DomainNameEncoding) {
  auto packet =
      builder_->set_id(1).add_question("www.example.com", RecordType::A, RecordClass::IN).build();

  // Find the encoded domain name in the packet (after header)
  size_t offset = 12;  // Skip header

  // Check encoding: 3www7example3com0
  EXPECT_EQ(packet[offset], 3);  // Length of "www"
  EXPECT_EQ(packet[offset + 1], 'w');
  EXPECT_EQ(packet[offset + 2], 'w');
  EXPECT_EQ(packet[offset + 3], 'w');
  EXPECT_EQ(packet[offset + 4], 7);  // Length of "example"
}

TEST_F(PacketTest, InvalidDomainName) {
  EXPECT_THROW(builder_->add_question("", RecordType::A, RecordClass::IN), ProtocolException);

  // Test very long label (>63 characters)
  std::string long_label(64, 'a');
  EXPECT_THROW(builder_->add_question(long_label + ".com", RecordType::A, RecordClass::IN),
               ProtocolException);
}

TEST_F(PacketTest, MultipleQuestions) {
  auto packet = builder_->set_id(1)
                    .add_question("example.com", RecordType::A, RecordClass::IN)
                    .add_question("google.com", RecordType::AAAA, RecordClass::IN)
                    .build();

  PacketParser parser(packet);
  auto message = parser.parse();

  EXPECT_EQ(message.header.qdcount, 2);
  ASSERT_EQ(message.questions.size(), 2u);

  EXPECT_EQ(message.questions[0].qname, "example.com");
  EXPECT_EQ(message.questions[0].qtype, RecordType::A);

  EXPECT_EQ(message.questions[1].qname, "google.com");
  EXPECT_EQ(message.questions[1].qtype, RecordType::AAAA);
}

TEST_F(PacketTest, ResponseWithAnswer) {
  std::vector<uint8_t> ipv4_addr = {192, 168, 1, 1};

  auto packet = builder_->set_id(0x5678)
                    .set_flags(true, 0, true, false, true, true, 0)
                    .add_question("test.com", RecordType::A, RecordClass::IN)
                    .add_answer("test.com", RecordType::A, RecordClass::IN, 3600, ipv4_addr)
                    .build();

  PacketParser parser(packet);
  auto message = parser.parse();

  EXPECT_TRUE(message.header.is_response());
  EXPECT_TRUE(message.header.is_authoritative());
  EXPECT_EQ(message.header.ancount, 1);

  ASSERT_EQ(message.answers.size(), 1u);
  EXPECT_EQ(message.answers[0].name, "test.com");
  EXPECT_EQ(message.answers[0].type, RecordType::A);
  EXPECT_EQ(message.answers[0].ttl, 3600u);
  EXPECT_EQ(message.answers[0].rdata, ipv4_addr);
}

TEST_F(PacketTest, CompressionPointer) {
  // Test name compression - this is a simplified test
  auto packet =
      builder_->set_id(1)
          .add_question("www.example.com", RecordType::A, RecordClass::IN)
          .add_answer("mail.example.com", RecordType::A, RecordClass::IN, 300, {1, 2, 3, 4})
          .build();

  // Verify packet can be parsed back correctly
  PacketParser parser(packet);
  auto message = parser.parse();

  EXPECT_EQ(message.questions[0].qname, "www.example.com");
  EXPECT_EQ(message.answers[0].name, "mail.example.com");
}

TEST_F(PacketTest, TruncatedPacket) {
  std::vector<uint8_t> truncated = {0x12, 0x34, 0x81, 0x80};  // Only partial header

  PacketParser parser(truncated);
  EXPECT_FALSE(parser.is_valid_packet());
  EXPECT_THROW(parser.parse(), ParseException);
}

TEST_F(PacketTest, MalformedPacket) {
  std::vector<uint8_t> malformed = {
      0x12, 0x34,  // ID
      0x81, 0x80,  // Flags
      0x00, 0x01,  // QDCOUNT (claims 1 question)
      0x00, 0x00,  // ANCOUNT
      0x00, 0x00,  // NSCOUNT
      0x00, 0x00,  // ARCOUNT
                   // But no question data follows
  };

  PacketParser parser(malformed);
  EXPECT_THROW(parser.parse(), ParseException);
}

// Test utility functions
TEST(PacketUtilsTest, ExtractQueryId) {
  std::vector<uint8_t> packet = {0xAB, 0xCD, 0x01, 0x00};
  auto id = packet_parsers::extract_query_id(packet);
  ASSERT_TRUE(id.has_value());
  EXPECT_EQ(*id, 0xABCD);
}

TEST(PacketUtilsTest, IsResponse) {
  std::vector<uint8_t> query = {0x12, 0x34, 0x01, 0x00};     // QR=0
  std::vector<uint8_t> response = {0x12, 0x34, 0x81, 0x00};  // QR=1

  EXPECT_FALSE(packet_parsers::is_dns_response(query));
  EXPECT_TRUE(packet_parsers::is_dns_response(response));
}

TEST(PacketUtilsTest, IsTruncated) {
  std::vector<uint8_t> normal = {0x12, 0x34, 0x81, 0x00};     // TC=0
  std::vector<uint8_t> truncated = {0x12, 0x34, 0x83, 0x00};  // TC=1

  EXPECT_FALSE(packet_parsers::is_truncated_response(normal));
  EXPECT_TRUE(packet_parsers::is_truncated_response(truncated));
}

TEST(PacketUtilsTest, ExtractResponseCode) {
  std::vector<uint8_t> no_error = {0x12, 0x34, 0x81, 0x00};    // RCODE=0
  std::vector<uint8_t> name_error = {0x12, 0x34, 0x81, 0x03};  // RCODE=3

  auto rcode1 = packet_parsers::extract_response_code(no_error);
  auto rcode2 = packet_parsers::extract_response_code(name_error);

  ASSERT_TRUE(rcode1.has_value());
  ASSERT_TRUE(rcode2.has_value());
  EXPECT_EQ(*rcode1, ResponseCode::NO_ERROR);
  EXPECT_EQ(*rcode2, ResponseCode::NAME_ERROR);
}
