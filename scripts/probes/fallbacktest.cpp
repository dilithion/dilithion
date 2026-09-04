// M4 evidence probe: when fs::rename DOES fail on Windows, what does the
// remove-then-rename fallback actually do?
//
//   g++ -std=c++17 -O1 -o fallbacktest.exe scripts/probes/fallbacktest.cpp && ./fallbacktest.exe
//
// Result on the shipped toolchain: in both realistic triggers (destination held
// open by another handle; destination read-only) fs::rename fails EACCES AND the
// fallback's remove() also fails (ERROR_SHARING_VIOLATION / ERROR_ACCESS_DENIED),
// so the destination survives. The fallback is dead code here -- but see
// killprobe_mik.cpp for what its shape does wherever it IS reached.

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>
namespace fs = std::filesystem;
#ifdef _WIN32
#include <windows.h>
#endif
static void mk(const char* p, const char* s){ std::ofstream o(p, std::ios::binary|std::ios::trunc); o<<s; }
int main(){
  // Trigger A: destination held open by another handle (AV scan, backup agent,
  // a second node process, an explorer preview).
  {
    mk("fb_dst.bin","OLD"); mk("fb_tmp.bin","NEW");
    HANDLE h = CreateFileW(L"fb_dst.bin", GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    printf("A. dst held open (handle=%s)\n", h==INVALID_HANDLE_VALUE?"FAIL":"ok");
    std::error_code ec; fs::rename("fb_tmp.bin","fb_dst.bin",ec);
    printf("   fs::rename         -> ec=%d (%s)\n", ec.value(), ec.message().c_str());
    if (ec) {
      bool removed = fs::remove("fb_dst.bin", ec);
      printf("   fallback remove    -> removed=%d ec=%d\n", (int)removed, ec.value());
      fs::rename("fb_tmp.bin","fb_dst.bin",ec);
      printf("   fallback rename    -> ec=%d\n", ec.value());
    }
    if (h!=INVALID_HANDLE_VALUE) CloseHandle(h);
    printf("   RESULT: dst exists=%d  tmp exists=%d\n",
           (int)fs::exists("fb_dst.bin"), (int)fs::exists("fb_tmp.bin"));
    // Same trigger, MoveFileExW:
    mk("fb2_dst.bin","OLD"); mk("fb2_tmp.bin","NEW");
    HANDLE h2 = CreateFileW(L"fb2_dst.bin", GENERIC_READ, FILE_SHARE_READ, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    BOOL ok = MoveFileExW(L"fb2_tmp.bin", L"fb2_dst.bin",
                          MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH);
    printf("   MoveFileExW        -> ok=%d err=%lu; dst exists=%d\n",
           (int)ok, ok?0UL:GetLastError(), (int)fs::exists("fb2_dst.bin"));
    if (h2!=INVALID_HANDLE_VALUE) CloseHandle(h2);
  }
  // Trigger B: destination marked read-only.
  {
    mk("fb3_dst.bin","OLD"); mk("fb3_tmp.bin","NEW");
    SetFileAttributesW(L"fb3_dst.bin", FILE_ATTRIBUTE_READONLY);
    std::error_code ec; fs::rename("fb3_tmp.bin","fb3_dst.bin",ec);
    printf("B. dst read-only\n   fs::rename         -> ec=%d (%s)\n", ec.value(), ec.message().c_str());
    if (ec) {
      bool removed = fs::remove("fb3_dst.bin", ec);
      printf("   fallback remove    -> removed=%d ec=%d\n", (int)removed, ec.value());
      fs::rename("fb3_tmp.bin","fb3_dst.bin",ec);
      printf("   fallback rename    -> ec=%d\n", ec.value());
    }
    printf("   RESULT: dst exists=%d  tmp exists=%d\n",
           (int)fs::exists("fb3_dst.bin"), (int)fs::exists("fb3_tmp.bin"));
    SetFileAttributesW(L"fb3_dst.bin", FILE_ATTRIBUTE_NORMAL);
  }
  return 0;
}
