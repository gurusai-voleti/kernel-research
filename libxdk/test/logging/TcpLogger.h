/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "test/logging/TapLogger.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <streambuf>
#include <string>
#include <vector>

class TcpStreambuf : public std::streambuf {
    int sock_ = -1;
    std::vector<char> buffer_;

public:
    TcpStreambuf(const std::string& host_port) {
        size_t colon_pos = host_port.find(':');
        if (colon_pos == std::string::npos) {
            std::cerr << "Invalid host:port format: " << host_port << std::endl;
            return;
        }

        std::string host = host_port.substr(0, colon_pos);
        int port = std::stoi(host_port.substr(colon_pos + 1));

        sock_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sock_ < 0) {
            perror("socket");
            return;
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(port);

        if (inet_pton(AF_INET, host.c_str(), &serv_addr.sin_addr) <= 0) {
            perror("inet_pton");
            return;
        }

        if (connect(sock_, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("connect");
            return;
        }
        
        // No buffering, or small buffering? Let's use internal buffering for efficiency
        // buffer_.resize(4096);
    }

    ~TcpStreambuf() {
        if (sock_ >= 0) {
            close(sock_);
        }
    }

protected:
    int overflow(int c) override {
        if (c != EOF) {
            char ch = c;
            if (sock_ >= 0) {
                send(sock_, &ch, 1, 0);
            }
        }
        return c;
    }

    std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (sock_ >= 0) {
            send(sock_, s, n, 0);
        }
        return n;
    }
};

class TcpLogger : public TapLogger {
    TcpStreambuf tcp_buf_;
    std::streambuf* old_cout_buf_;

public:
    TcpLogger(const std::string& host_port) : tcp_buf_(host_port), old_cout_buf_(nullptr) {}

    void Begin(const std::vector<std::unique_ptr<TestSuite>>& test_suites, uint test_count) override {
        // Redirect cout to tcp
        old_cout_buf_ = std::cout.rdbuf(&tcp_buf_);
        TapLogger::Begin(test_suites, test_count);
    }

    void End() override {
        TapLogger::End();
        // Restore cout
        if (old_cout_buf_) {
            std::cout.rdbuf(old_cout_buf_);
        }
    }

    ~TcpLogger() {
        if (old_cout_buf_ && std::cout.rdbuf() == &tcp_buf_) {
            std::cout.rdbuf(old_cout_buf_);
        }
    }
};
