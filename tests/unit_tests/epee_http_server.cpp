// Copyright (c) 2014-2024, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//

#include <atomic>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#ifdef SALVIUM_STANDALONE_HTTP_TEST
#include <iostream>
#include <stdexcept>
#define TEST(suite, name) void suite##_##name()
#define EXPECT_FALSE(value) do { if (value) throw std::runtime_error("Expected false at line " + std::to_string(__LINE__) + ": " #value); } while (0)
#define EXPECT_TRUE(value) do { if (!(value)) throw std::runtime_error("Expected true: " #value); } while (0)
#define EXPECT_EQ(a, b) do { if ((a) != (b)) throw std::runtime_error("Expected equality: " #a " and " #b); } while (0)
#else
#include "gtest/gtest.h"
#endif
#include "net/http_server_handlers_map2.h"
#include "net/http_server_impl_base.h"
#include "storages/portable_storage_template_helper.h"

namespace
{
  constexpr const std::size_t payload_size = 26 * 1024 * 1024;
  constexpr const std::size_t max_private_ips = 25;
  struct dummy
  {
    struct request
    {
      BEGIN_KV_SERIALIZE_MAP()
      END_KV_SERIALIZE_MAP()
    };

    struct response
    {
      BEGIN_KV_SERIALIZE_MAP()
        KV_SERIALIZE(payload)
      END_KV_SERIALIZE_MAP()

      std::string payload;
    };
  };

  std::string make_payload()
  {
    dummy::request body{};
    const auto body_serialized = epee::serialization::store_t_to_binary(body);
    return std::string{
      reinterpret_cast<const char*>(body_serialized.data()),
      body_serialized.size()
    };
  }

  struct http_server :  epee::http_server_impl_base<http_server>
  {
    using connection_context =  epee::net_utils::connection_context_base;

    http_server()
      : epee::http_server_impl_base<http_server>(),
        dummy_size(payload_size)
    {}

    CHAIN_HTTP_TO_MAP2(connection_context); //forward http requests to uri map

    BEGIN_URI_MAP2()
      MAP_URI_AUTO_BIN2("/dummy", on_dummy, dummy)
    END_URI_MAP2()

    bool on_dummy(const dummy::request&, dummy::response& res, const connection_context *ctx = NULL)
    {
      res.payload.resize(dummy_size.load(), 'f');
      return true;
    }

    std::atomic<std::size_t> dummy_size;
  };
} // anonymous

TEST(http_server, response_soft_limit)
{
  namespace http = boost::beast::http;

  http_server server{};
  EXPECT_TRUE(server.init(nullptr, "0", "127.0.0.1"));
  server.run(1, false);
  const auto stop = epee::misc_utils::create_scope_leave_handler([&] { server.send_stop_signal(); });

  boost::system::error_code error{};
  boost::asio::io_context context{};
  boost::asio::ip::tcp::socket stream{context};
  stream.connect(
    boost::asio::ip::tcp::endpoint{
      boost::asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(server.get_binded_port())
    },
    error
  );
  EXPECT_FALSE(bool(error));

  http::request<http::string_body> req{http::verb::get, "/dummy", 11};
  req.set(http::field::host, "127.0.0.1");
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.body() = make_payload();
  req.prepare_payload();
  http::write(stream, req, error);
  EXPECT_FALSE(bool(error));

  {
    dummy::response payload{};
    boost::beast::flat_buffer buffer;
    http::response_parser<http::string_body> parser;
    parser.body_limit(payload_size + 1024);
    http::read(stream, buffer, parser, error);
    auto res = parser.release();
    EXPECT_FALSE(bool(error));
    EXPECT_EQ(200u, res.result_int());
    EXPECT_TRUE(epee::serialization::load_t_from_binary(payload, res.body()));
    EXPECT_EQ(payload_size, std::count(payload.payload.begin(), payload.payload.end(), 'f'));
  }

  while (!error)
    http::write(stream, req, error);
  server.send_stop_signal();
}

TEST(http_server, private_ip_limit)
{
  namespace http = boost::beast::http;

  http_server server{};
  server.dummy_size = 1;
  EXPECT_TRUE(server.init(nullptr, "0", "127.0.0.1"));
  server.run(1, false);
  const auto stop = epee::misc_utils::create_scope_leave_handler([&] { server.send_stop_signal(); });

  boost::system::error_code error{};
  boost::asio::io_context context{};

  http::request<http::string_body> req{http::verb::get, "/dummy", 11};
  req.set(http::field::host, "127.0.0.1");
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
  req.body() = make_payload();
  req.prepare_payload();

  std::vector<boost::asio::ip::tcp::socket> streams{};
  for (std::size_t i = 0; i < max_private_ips; ++i)
  {
    streams.emplace_back(context);
    streams.back().connect(
      boost::asio::ip::tcp::endpoint{
        boost::asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(server.get_binded_port())
      },
      error
    );
    http::write(streams.back(), req, error);
    EXPECT_FALSE(bool(error));

    dummy::response payload{};
    boost::beast::flat_buffer buffer;
    http::response<http::basic_string_body<char>> res;

    http::read(streams.back(), buffer, res, error);
    EXPECT_FALSE(bool(error));
  }

  boost::asio::ip::tcp::socket stream{context};
  stream.connect(
    boost::asio::ip::tcp::endpoint{
      boost::asio::ip::make_address("127.0.0.1"), static_cast<unsigned short>(server.get_binded_port())
    },
    error
  );
  bool failed = bool(error);
  http::write(stream, req, error);
  failed |= bool(error);
  {
    dummy::response payload{};
    boost::beast::flat_buffer buffer;
    http::response<http::basic_string_body<char>> res;

    // make sure server ran async_accept code
    http::read(stream, buffer, res, error);
  }
  failed |= bool(error);
  EXPECT_TRUE(failed);
}

#ifdef SALVIUM_STANDALONE_HTTP_TEST
int main() {
  try {
    http_server_response_soft_limit();
    http_server_private_ip_limit();
    std::cout << "PASS: HTTP response queue and connection limits on isolated loopback ports\n";
    return 0;
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
#endif
