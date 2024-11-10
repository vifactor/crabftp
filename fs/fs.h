#ifndef FS_H
#define FS_H

#include <string>
#include <filesystem>

std::string listDirContents(const std::filesystem::path& path);

#endif // FS_H
