// M4 evidence probe: what does std::filesystem::rename ACTUALLY do on Windows?
//
//   g++ -std=c++17 -O1 -o renametest.exe scripts/probes/renametest.cpp && ./renametest.exe
//
// Result on MinGW-w64 GCC 15.2 / __GLIBCXX__ 20250808 (the shipped toolchain):
//   1. fs::rename over existing  : ec=0  -> dst replaced (atomic replace)
//   2. std::rename over existing : rc=-1 errno=17 (EEXIST) -> dst unchanged
//   3. fs::rename, dst held open : ec=13 (Permission denied)
//   4. fs::rename, dst read-only : ec=13 (Permission denied)
// (1) falsifies the common claim that fs::rename cannot replace on Windows.
// (2) shows the claim IS true of the C library call, which is where it comes from.

#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>
namespace fs = std::filesystem;
static void mk(const char* p, const char* s){ std::ofstream o(p, std::ios::binary|std::ios::trunc); o<<s; }
static std::string rd(const char* p){ std::ifstream i(p, std::ios::binary); std::string s((std::istreambuf_iterator<char>(i)),std::istreambuf_iterator<char>()); return s; }
int main(){
  printf("__GLIBCXX__ = %ld\n", (long)__GLIBCXX__);
  { // 1. fs::rename over an existing destination
    mk("rt_dst.bin","OLD"); mk("rt_tmp.bin","NEW");
    std::error_code ec; fs::rename("rt_tmp.bin","rt_dst.bin",ec);
    printf("1. fs::rename over existing : ec=%d (%s) dst=%s tmp_exists=%d\n",
           ec.value(), ec.message().c_str(), rd("rt_dst.bin").c_str(), (int)fs::exists("rt_tmp.bin"));
  }
  { // 2. C std::rename over an existing destination
    mk("rt_dst2.bin","OLD"); mk("rt_tmp2.bin","NEW");
    int r = std::rename("rt_tmp2.bin","rt_dst2.bin");
    printf("2. std::rename over existing: rc=%d errno=%d dst=%s\n", r, errno, rd("rt_dst2.bin").c_str());
  }
  { // 3. fs::rename while the destination is held OPEN by this process
    mk("rt_dst3.bin","OLD"); mk("rt_tmp3.bin","NEW");
    std::ifstream hold("rt_dst3.bin", std::ios::binary);
    std::error_code ec; fs::rename("rt_tmp3.bin","rt_dst3.bin",ec);
    printf("3. fs::rename, dst open     : ec=%d (%s)\n", ec.value(), ec.message().c_str());
  }
  { // 4. fs::rename onto a DIRECTORY-in-the-way / read-only dst
    mk("rt_dst4.bin","OLD"); mk("rt_tmp4.bin","NEW");
    fs::permissions("rt_dst4.bin", fs::perms::owner_read, fs::perm_options::replace);
    std::error_code ec; fs::rename("rt_tmp4.bin","rt_dst4.bin",ec);
    printf("4. fs::rename, dst readonly : ec=%d (%s)\n", ec.value(), ec.message().c_str());
    fs::permissions("rt_dst4.bin", fs::perms::owner_all, fs::perm_options::replace);
  }
  return 0;
}
