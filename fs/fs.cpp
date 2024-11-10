#include "fs.h"

#include <iostream>

namespace {
std::string toString(std::filesystem::perms p)
{
    std::string result;
    using std::filesystem::perms;
    auto set = [&](char op, perms perm)
    {
        result += (perms::none == (perm & p) ? '-' : op);
    };
    set('r', perms::owner_read);
    set('w', perms::owner_write);
    set('x', perms::owner_exec);
    set('r', perms::group_read);
    set('w', perms::group_write);
    set('x', perms::group_exec);
    set('r', perms::others_read);
    set('w', perms::others_write);
    set('x', perms::others_exec);

    return result;
}

// https://stackoverflow.com/a/61067330
template <typename T>
std::time_t toTimeT(T tp)
{
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(tp - T::clock::now()
                                                        + system_clock::now());
    return system_clock::to_time_t(sctp);
}

unsigned toYear(const std::time_t& t)
{
    std::tm now_tm = *std::localtime(&t);
    return now_tm.tm_year + 1900;
}

unsigned filesCount(const std::filesystem::path& path)
{
    return std::distance(std::filesystem::directory_iterator(path), std::filesystem::directory_iterator{});
}

}

// "drwxr-xr-x 2 1000 1000 4096 Mar  1 10:00 ..\n"
// "-rw-r--r-- 1 1000 1000  220 Mar  1 10:00 file1.txt\n"
std::string listDirContents(const std::filesystem::path &path)
{
    std::string result;
    for (const auto &entry : std::filesystem::directory_iterator(path))
    {
        auto status = entry.status();

        bool isDirectory = std::filesystem::is_directory(status);
        result += (isDirectory ? "d" : "-");
        result += toString(status.permissions()) + " ";

        // the number of links the resource has
        const auto linksCount = isDirectory ? filesCount(entry.path()) : 1;
        result += std::to_string(linksCount) + " ";

        // we do not care about user and group so far
        result += "owner group ";

        auto size = [&]() {
            try {
                return isDirectory ? 0 : entry.file_size();
            } catch (const std::exception &e) {
                std::cerr << e.what();
                return uintmax_t{};
            }
        }();
        result += std::to_string(size) + " ";

        auto fileTime = entry.last_write_time();
        auto fileTimeT = ::toTimeT(fileTime);
        // if this year, then show time, otherwise show year
        const auto dateFormat =
            (toYear(fileTimeT) == toYear(std::time(nullptr))) ? "%b %e %H:%M" : "%b %e  %Y";

        std::string s(30, '\0');
        const auto nchars = std::strftime(s.data(), s.size(), dateFormat, std::localtime(&fileTimeT));
        s.resize(nchars);
        result += s + " ";

        result += entry.path().filename().string() + "\n";
    }

    std::cout << path.string() << ":\n" << result << std::endl;

    return result;
}
