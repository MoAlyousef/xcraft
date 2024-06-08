#pragma once

#include <memory>
#include <string_view>

namespace ctf {

class Tube {
  public:
    virtual void writeln(std::string_view msg) = 0;
    virtual void write(std::string_view msg)   = 0;
    virtual void write(char msg)               = 0;
    virtual std::string readn(int n)           = 0;
    virtual std::string readln()               = 0;
    virtual std::string readall()              = 0;
    virtual void interactive()                 = 0;
    virtual ~Tube()                            = 0;
};

class Process : public Tube {
    friend class Gdb;
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    Process(std::string_view args, std::string_view env = "");
    void writeln(std::string_view msg) override;
    void write(std::string_view msg) override;
    void write(char msg) override;
    std::string readn(int n) override;
    std::string readln() override;
    std::string readall() override;
    void interactive() override;
    int exit_status();
};

class Remote : public Tube {
    struct Impl;
    std::shared_ptr<Impl> pimpl;

  public:
    Remote(std::string_view url, unsigned short port);
    void write(std::string_view msg) override;
    void writeln(std::string_view msg) override;
    void write(char msg) override;
    std::string readn(int n) override;
    std::string readln() override;
    std::string readall() override;
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