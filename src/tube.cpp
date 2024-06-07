#include <asio.hpp>
#include <cstdio>
#include <cstring>
#include <ctf/context.hpp>
#include <ctf/tube.hpp>
#include <fmt/core.h>
#include <fmt/format.h>
#include <fmt/ostream.h>
#include <fmt/ranges.h>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <subprocess.h>
#include <thread>

static std::vector<const char *> split_strings(
    char *str, const char *delimiter
) {
    std::vector<const char *> v;
    const char *token = strtok(str, delimiter);
    while (token != nullptr) {
        v.push_back(token);
        token = strtok(nullptr, delimiter);
    }

    return v;
}

static void write_gdb_script(
    const char *script_path,
    unsigned short port,
    std::string_view gdb_server_args
) {
    std::ofstream script;
    script.open(script_path);
    if (script.is_open()) {
        fmt::print(
            script, "target remote localhost:{}\n{}\n", port, gdb_server_args
        );
    } else {
        throw std::runtime_error("Failed to write GDB script");
    }
}

namespace ctf {

Tube::~Tube() = default;

struct Process::Impl {
    struct subprocess_s subprocess {};
    Impl(std::string_view args, std::string_view env) {
        bool env_empty = env.size() == 0;
        auto args0     = std::string(args);
        auto args1     = split_strings(args0.data(), " ");
        args1.push_back(nullptr);
        std::vector<const char *> env1;
        if (!env_empty) {
            auto env0 = std::string(env);
            env1      = split_strings(env0.data(), ";");
            env1.push_back(nullptr);
        }
        int flags = subprocess_option_combined_stdout_stderr |
                    subprocess_option_no_window |
                    subprocess_option_search_user_path;
        if (env_empty)
            flags |= subprocess_option_inherit_environment;
        int result = subprocess_create_ex(
            args1.data(), flags, env_empty ? nullptr : env1.data(), &subprocess
        );
        if (0 != result) {
            throw std::runtime_error(
                fmt::format("Failed to launch process {}", args1[0])
            );
        }
        (void)fflush(nullptr);
    }
    ~Impl() { subprocess_destroy(&subprocess); }
};

Process::Process(std::string_view args, std::string_view env)
    : pimpl(new Process::Impl(args, env)) {}

std::vector<unsigned char> Process::readn(int n) {
    std::vector<unsigned char> ret(n, 0);
    int i  = 0;
    int ch = 0;
    while (EOF != (ch = fgetc(pimpl->subprocess.stdout_file)) && i < n) {
        ret[i] = (unsigned char)ch;
        i++;
    }
    return ret;
}

std::vector<unsigned char> Process::readln() {
    std::vector<unsigned char> ret;
    int ch = 0;
    do {
        ch = fgetc(pimpl->subprocess.stdout_file);
        if (ch == '\n')
            break;
        ret.push_back((unsigned char)ch);
    } while (EOF != ch);
    return ret;
}

std::vector<unsigned char> Process::readall() {
    std::vector<unsigned char> ret;
    int ch = 0;
    do {
        ch = fgetc(pimpl->subprocess.stdout_file);
        ret.push_back((unsigned char)ch);
    } while (EOF != ch);
    return ret;
}

void Process::write(std::span<const unsigned char> message) {
    for (auto e : message)
        (void)fputc((int)e, pimpl->subprocess.stdin_file);
    (void)fflush(pimpl->subprocess.stdin_file);
}

void Process::writeln(std::span<const unsigned char> message) {
    for (auto e : message)
        (void)fputc((int)e, pimpl->subprocess.stdin_file);
    (void)fputc('\n', pimpl->subprocess.stdin_file);
    (void)fflush(pimpl->subprocess.stdin_file);
}

void Process::write(unsigned char message) {
    (void)fputc((int)message, pimpl->subprocess.stdin_file);
    (void)fflush(pimpl->subprocess.stdin_file);
}

void Process::interactive() {
    auto impl = pimpl;
    auto in   = impl->subprocess.stdin_file;
    auto out  = impl->subprocess.stdout_file;
    std::thread t([=] {
        int ch = 0;
        while (EOF != (ch = fgetc(out))) {
            (void)fputc(ch, stdout);
            (void)fflush(stdout);
        }
    });
    std::string line;
    while (std::getline(std::cin, line)) {
        try {
            line += '\n';
            fmt::print(in, "{}", line);
            (void)fflush(in);
        } catch (...) {
            break;
        }
    }
    t.join();
    int ret_status = 0;
    subprocess_join(&impl->subprocess, &ret_status);
    fmt::println(stderr, "Pipe close with {}", ret_status);
}

int Process::exit_status() {
    int ret_status = 0;
    subprocess_join(&pimpl->subprocess, &ret_status);
    return ret_status;
}

using asio::ip::tcp;

struct Remote::Impl {
    asio::io_context io_context_;
    tcp::socket socket_;

    Impl(std::string_view url, unsigned short port)
        : io_context_(), socket_(io_context_) {
        tcp::resolver resolver(io_context_);
        auto endpoints = resolver.resolve(url, std::to_string(port));
        asio::connect(socket_, endpoints);
        (void)fflush(nullptr);
    }
};

Remote::Remote(std::string_view url, unsigned short port)
    : pimpl(std::make_shared<Remote::Impl>(url, port)) {}

std::vector<unsigned char> Remote::readn(int n) {
    std::vector<unsigned char> ret(n, 0);
    asio::error_code ec;
    asio::read(
        pimpl->socket_, asio::buffer(ret), asio::transfer_exactly(n), ec
    );
    return ret;
}

std::vector<unsigned char> Remote::readln() {
    std::vector<unsigned char> ret;
    asio::error_code ec;
    asio::read_until(pimpl->socket_, asio::dynamic_buffer(ret), '\n', ec);
    return ret;
}

std::vector<unsigned char> Remote::readall() {
    std::vector<unsigned char> ret;
    asio::error_code ec;
    asio::read(
        pimpl->socket_, asio::dynamic_buffer(ret), ec
    );
    return ret;
}

void Remote::writeln(std::span<const unsigned char> message) {
    asio::write(pimpl->socket_, asio::buffer(message));
    std::array<unsigned char, 1> buf = {'\n'};
    asio::write(pimpl->socket_, asio::buffer(buf));
}

void Remote::write(std::span<const unsigned char> message) {
    asio::write(pimpl->socket_, asio::buffer(message));
}

void Remote::write(unsigned char message) {
    std::array<unsigned char, 1> buf = {message};
    asio::write(pimpl->socket_, asio::buffer(buf));
}

void Remote::interactive() {
    constexpr size_t buf_size = 1024;
    std::array<char, buf_size> read_{};
    pimpl->socket_.async_read_some(
        asio::buffer(read_, buf_size),
        [&](auto ec, size_t transferred) {
            fmt::print("{}", std::string_view(read_.data(), transferred));
        }
    );
    std::thread t([this] { pimpl->io_context_.run(); });
    std::string line;
    while (std::getline(std::cin, line)) {
        try {
            line += '\n';
            asio::write(pimpl->socket_, asio::buffer(line));
        } catch (...) {
            break;
        }
    }
    t.join();
    fmt::println(stderr, "Remote closed");
}

constexpr unsigned short DEFAULT_GDB_SERVER_PORT = 1234;
constexpr int DEFAULT_SLEEP_MILLIS               = 16;

#ifndef _WIN32
int Gdb::attach(const Process &pp, std::string_view gdb_server_args) {
    const char *script_path = "/tmp/gdb_script.txt";
    unsigned short port     = DEFAULT_GDB_SERVER_PORT;
    write_gdb_script(script_path, port, gdb_server_args);
    std::string gdb_args =
        fmt::format("{} gdb -x {} -q", CONTEXT.terminal, script_path);
    std::string gdb_server_cmd = fmt::format(
        "gdbserver localhost:{} --attach {}", port, pp.pimpl->subprocess.child
    );
    auto p = Process(gdb_server_cmd.c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_SLEEP_MILLIS)
    );
    auto proc     = Process{gdb_args.c_str()};
    auto to_write = fmt::format("attach {}\n", pp.pimpl->subprocess.child);
    proc.write(std::span<const unsigned char>(
        reinterpret_cast<unsigned char *>(to_write.data()), to_write.size()
    ));
    return p.pimpl->subprocess.child;
}
#endif

Process Gdb::debug(std::string_view pp, std::string_view gdb_server_args) {
    const char *script_path = "/tmp/gdb_script.txt";
    unsigned short port     = DEFAULT_GDB_SERVER_PORT;
    write_gdb_script(script_path, port, gdb_server_args);
    std::string gdb_args =
        fmt::format("{} gdb -x {} -q {}", CONTEXT.terminal, script_path, pp);
    std::string gdb_server_cmd =
        fmt::format("gdbserver localhost:{} {}", port, pp);
    auto p = Process(gdb_server_cmd.c_str());
    std::this_thread::sleep_for(std::chrono::milliseconds(DEFAULT_SLEEP_MILLIS)
    );
    auto proc = Process{gdb_args.c_str()};
    return p;
}
} // namespace ctf