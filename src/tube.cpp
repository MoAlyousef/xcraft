#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <asio.hpp>
#include <fmt/format.h>
#include <subprocess.h>

#include <xcraft/context.hpp>
#include <xcraft/tube.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

using asio::ip::tcp;

namespace {

static std::vector<std::string> split_string(std::string_view s, char delim) {
    std::vector<std::string> out;
    std::string current;
    bool in_quote = false;

    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '\\' && i + 1 < s.size()) {
            current.push_back(s[++i]);
        } else if (c == '"') {
            in_quote = !in_quote;
        } else if (c == delim && !in_quote) {
            out.emplace_back(std::move(current));
            current.clear();
        } else {
            current.push_back(c);
        }
    }
    out.emplace_back(std::move(current));
    return out;
}

struct TempFile {
    std::filesystem::path path;

    explicit TempFile(const std::string &suffix = ".tmp") {
#ifdef _WIN32
        char tmpPath[MAX_PATH];
        if (::GetTempPathA(MAX_PATH, tmpPath) == 0)
            throw std::runtime_error("GetTempPathA failed");
        char tmpFile[MAX_PATH];
        if (::GetTempFileNameA(tmpPath, "xcft", 0, tmpFile) == 0)
            throw std::runtime_error("GetTempFileNameA failed");
        path = std::string(tmpFile) + suffix;
        std::error_code ec;
        std::filesystem::rename(tmpFile, path, ec);
        if (ec)
            throw std::runtime_error(
                "Failed to rename temp file: " + ec.message()
            );
#else
        auto dir = std::filesystem::temp_directory_path();
        std::string pattern =
            (dir / std::filesystem::path("xcftXXXXXX" + suffix)).string();
        std::vector<char> buf(pattern.begin(), pattern.end());
        buf.push_back('\0');
        int fd = ::mkstemp(buf.data());
        if (fd == -1)
            throw std::system_error(
                errno, std::generic_category(), "mkstemp failed"
            );
        ::close(fd);
        path = buf.data();
#endif
        std::ofstream ofs(path.string(), std::ios::app);
        if (!ofs)
            throw std::runtime_error(
                "Failed to create TempFile: " + path.string()
            );
    }

    TempFile(const TempFile &)            = delete;
    TempFile &operator=(const TempFile &) = delete;
    TempFile(TempFile &&)                 = delete;
    TempFile &operator=(TempFile &&)      = delete;

    ~TempFile() {
        std::error_code ec;
        std::filesystem::remove(path, ec);
    }

    operator std::string() const { return path.string(); }
};

static void write_gdb_script(
    const std::filesystem::path &p, uint16_t port, std::string_view extra
) {
    std::ofstream fs(p);
    if (!fs)
        throw std::runtime_error("Failed to write GDB script");
    fs << fmt::format("target remote localhost:{}\n{}\n", port, extra);
}

} // namespace

namespace xcft {

struct SubprocessWrapper {
    subprocess_s s{};
    SubprocessWrapper()                                     = default;
    SubprocessWrapper(const SubprocessWrapper &)            = delete;
    SubprocessWrapper &operator=(const SubprocessWrapper &) = delete;
    SubprocessWrapper(SubprocessWrapper &&)                 = delete;
    SubprocessWrapper &operator=(SubprocessWrapper &&)      = delete;
    ~SubprocessWrapper() { subprocess_destroy(&s); }
    subprocess_s *get() { return &s; }
};

struct Process::Impl {
    std::vector<std::string> argv_store;
    std::vector<std::string> env_store;
    std::vector<const char *> argv_c;
    std::vector<const char *> envp_c;

    SubprocessWrapper proc;

    Impl(std::string_view args, std::string_view env) {
        argv_store = split_string(args, ' ');
        argv_c.reserve(argv_store.size() + 1);
        for (auto &s : argv_store)
            argv_c.push_back(s.c_str());
        argv_c.push_back(nullptr);

        if (!env.empty()) {
            env_store = split_string(env, ';');
            envp_c.reserve(env_store.size() + 1);
            for (auto &e : env_store)
                envp_c.push_back(e.c_str());
            envp_c.push_back(nullptr);
        }

        int flags = subprocess_option_combined_stdout_stderr |
                    subprocess_option_no_window |
                    subprocess_option_search_user_path;

        if (env.empty())
            flags |= subprocess_option_inherit_environment;

        int rc = subprocess_create_ex(
            argv_c.data(),
            flags,
            env.empty() ? nullptr : envp_c.data(),
            proc.get()
        );
        if (rc != 0)
            throw std::runtime_error(
                "Failed to launch process: " + argv_store.front()
            );
    }
};

Process::Process(std::string_view args, std::string_view env)
    : Tube(), pimpl(std::make_unique<Impl>(args, env)) {}

static std::string read_stream(FILE *f, std::function<bool(int)> pred) {
    std::string out;
    int ch = EOF;
    while ((ch = fgetc(f)) != EOF) {
        if (pred && pred(ch))
            break;
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

std::string Process::readn(int n) {
    std::string out;
    out.reserve(n);
    FILE *f = pimpl->proc.get()->stdout_file;
    while (n-- > 0) {
        int ch = fgetc(f);
        if (ch == EOF)
            break;
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

std::string Process::readln() {
    return read_stream(pimpl->proc.get()->stdout_file, [](int c) {
        return c == '\n';
    });
}

std::string Process::readall() {
    return read_stream(pimpl->proc.get()->stdout_file, nullptr);
}

static void write_raw(FILE *f, std::string_view s) {
    (void)fwrite(s.data(), 1, s.size(), f);
    (void)fflush(f);
}
void Process::write(std::string_view s) {
    write_raw(pimpl->proc.get()->stdin_file, s);
}
void Process::writeln(std::string_view s) {
    write_raw(pimpl->proc.get()->stdin_file, s),
        write_raw(pimpl->proc.get()->stdin_file, "\n");
}
void Process::write(char c) {
    (void)fputc(c, pimpl->proc.get()->stdin_file);
    (void)fflush(pimpl->proc.get()->stdin_file);
}

void Process::interactive() {
    auto *out = pimpl->proc.get()->stdout_file;

    std::atomic<bool> stop{false};
    std::thread t([&] {
        while (!stop) {
            int ch = fgetc(out);
            if (ch == EOF)
                break;
            (void)fputc(ch, stdout);
            (void)fflush(stdout);
        }
    });

    std::string line;
    while (std::getline(std::cin, line)) {
        if (line.empty())
            break;
        writeln(line);
    }
    stop = true;
    t.join();
}

int Process::exit_status() {
    int status = 0;
    subprocess_join(pimpl->proc.get(), &status);
    return status;
}

struct Remote::Impl {
    asio::io_context io;
    tcp::socket sock;
    Impl(std::string_view host, uint16_t port) : io(), sock(io) {
        tcp::resolver res(io);
        asio::connect(sock, res.resolve(host, std::to_string(port)));
        sock.set_option(tcp::no_delay{true});
    }
};

Remote::Remote(std::string_view host, uint16_t port)
    : Tube(), pimpl(std::make_shared<Impl>(host, port)) {}

std::string Remote::readn(int n) {
    std::string out(n, '\0');
    asio::read(pimpl->sock, asio::buffer(out), asio::transfer_exactly(n));
    return out;
}
std::string Remote::readln() {
    std::string out;
    asio::read_until(pimpl->sock, asio::dynamic_buffer(out), '\n');
    return out;
}
std::string Remote::readall() {
    std::string out;
    asio::error_code ec;
    asio::read(pimpl->sock, asio::dynamic_buffer(out), ec);
    if (ec && ec != asio::error::eof)
        throw std::system_error(ec);
    return out;
}

void Remote::write(std::string_view s) {
    asio::write(pimpl->sock, asio::buffer(s));
}
void Remote::writeln(std::string_view s) {
    write(s);
    write("\n");
}
void Remote::write(char c) { asio::write(pimpl->sock, asio::buffer(&c, 1)); }

void Remote::interactive() {
    std::array<char, 1024> buf{};
    std::atomic<bool> done{false};

    std::function<void()> start_read;
    start_read = [&] {
        pimpl->sock.async_read_some(
            asio::buffer(buf),
            [&, this](asio::error_code ec, std::size_t n) {
                if (!ec && n) {
                    std::cout.write(buf.data(), static_cast<long>(n));
                    std::cout.flush();
                    start_read();
                } else {
                    done = true;
                }
            }
        );
    };
    start_read();
    std::thread io_thr([&] { pimpl->io.run(); });

    std::string line;
    while (!done && std::getline(std::cin, line))
        writeln(line);

    done = true;
    pimpl->sock.close();
    io_thr.join();
}

constexpr uint16_t DEFAULT_GDB_PORT = 1234;
constexpr auto DEFAULT_SLEEP        = std::chrono::milliseconds(16);

#ifndef _WIN32
int Gdb::attach(const Process &pp, std::string_view extra) {
    TempFile script(".gdb");
    write_gdb_script(script.path, DEFAULT_GDB_PORT, extra);

    Process gs(
        fmt::format(
            "gdbserver localhost:{} --attach {}",
            DEFAULT_GDB_PORT,
            pp.pimpl->proc.get()->child
        ),
        ""
    );

    std::this_thread::sleep_for(DEFAULT_SLEEP);

    Process gdb(
        fmt::format("{} gdb -x {} -q", CONTEXT.terminal, script.path.string()),
        ""
    );
    gdb.write(fmt::format("attach {}\n", pp.pimpl->proc.get()->child));
    return pp.pimpl->proc.get()->child;
}
#endif

Process Gdb::debug(std::string_view program, std::string_view extra) {
    TempFile script(".gdb");
    write_gdb_script(script.path, DEFAULT_GDB_PORT, extra);

    Process gs(
        fmt::format("gdbserver localhost:{} {}", DEFAULT_GDB_PORT, program), ""
    );
    std::this_thread::sleep_for(DEFAULT_SLEEP);

    Process gdb(
        fmt::format(
            "{} gdb -x {} -q {}",
            CONTEXT.terminal,
            script.path.string(),
            program
        ),
        ""
    );
    return gs;
}

} // namespace xcft