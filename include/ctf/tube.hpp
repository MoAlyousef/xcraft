#pragma once

#include <memory>
#include <span>
#include <string_view>
#include <vector>

namespace ctf {

class Tube {
  public:
    virtual void writeln(std::span<const unsigned char> msg) = 0;
    virtual void write(std::span<const unsigned char> msg)   = 0;
    virtual void write(unsigned char msg)                    = 0;
    virtual std::vector<unsigned char> readn(int n)          = 0;
    virtual std::vector<unsigned char> readln()              = 0;
    virtual std::vector<unsigned char> readall()             = 0;
    virtual void interactive()                               = 0;
    virtual ~Tube()                                          = 0;
};

class Process : public Tube {
    friend class Gdb;
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    Process(std::string_view args, std::string_view env = "");
    void writeln(std::span<const unsigned char> msg) override;
    void write(std::span<const unsigned char> msg) override;
    void write(unsigned char msg) override;
    std::vector<unsigned char> readn(int n) override;
    std::vector<unsigned char> readln() override;
    std::vector<unsigned char> readall() override;
    void interactive() override;
    int exit_status();
};

class Remote : public Tube {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    Remote(std::string_view url, unsigned short port);
    void write(std::span<const unsigned char> msg) override;
    void writeln(std::span<const unsigned char> msg) override;
    void write(unsigned char msg) override;
    std::vector<unsigned char> readn(int n) override;
    std::vector<unsigned char> readln() override;
    std::vector<unsigned char> readall() override;
    void interactive() override;
};

struct Gdb {
#ifndef _WIN32
    static int attach(const Process &pp, std::string_view gdb_server_args = "");
#endif
    static Process debug(
        std::string_view pp, std::string_view gdb_server_args = ""
    );
};
} // namespace ctf