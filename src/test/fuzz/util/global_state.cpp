// Copyright (c) 2025-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/util/global_state.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

namespace global_state {
namespace {

//! A contiguous span of the main program's writable global memory.
struct Region {
    const std::byte* addr;
    std::size_t len;
    std::vector<std::byte> baseline;
};

//! A data symbol from the main program's symbol table, used to name drift.
struct Symbol {
    const std::byte* addr;
    std::size_t size;
    std::string name;
};

std::vector<Region> g_regions;
std::vector<Symbol> g_symbols; // sorted by addr
const std::byte* g_main_base{nullptr};

//! Collect the writable PT_LOAD segments of the main program only. The fuzz
//! target and all of Bitcoin Core are linked into it; shared libraries hold
//! runtime/allocator bookkeeping that is not the target's own state.
int CollectCallback(dl_phdr_info* info, std::size_t /*size*/, void* /*data*/)
{
    if (info->dlpi_name != nullptr && info->dlpi_name[0] != '\0') return 0; // not the main program
    g_main_base = reinterpret_cast<const std::byte*>(info->dlpi_addr);
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr{info->dlpi_phdr[i]};
        if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_W) == 0) continue;
        const auto* begin{reinterpret_cast<const std::byte*>(info->dlpi_addr + phdr.p_vaddr)};
        g_regions.push_back({begin, phdr.p_memsz, {}});
    }
    return 0;
}

//! Parse the main program's .symtab so drift can be reported with the real
//! symbol name. dladdr() only sees .dynsym and would leave internal-linkage
//! globals such as g_mock_steady_time unnamed. Requires an unstripped binary
//! (the standalone fuzz build is not stripped).
void LoadMainSymbols()
{
    const int fd{open("/proc/self/exe", O_RDONLY | O_CLOEXEC)};
    if (fd < 0) return;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size <= 0) {
        close(fd);
        return;
    }
    const auto file_size{static_cast<std::size_t>(st.st_size)};
    void* map{mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fd, 0)};
    close(fd);
    if (map == MAP_FAILED) return;

    const auto* file{static_cast<const char*>(map)};
    const auto* ehdr{reinterpret_cast<const ElfW(Ehdr)*>(file)};
    const auto* shdrs{reinterpret_cast<const ElfW(Shdr)*>(file + ehdr->e_shoff)};

    const ElfW(Shdr)* symtab{nullptr};
    for (unsigned i = 0; i < ehdr->e_shnum; ++i) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = &shdrs[i];
            break;
        }
    }
    if (symtab != nullptr && symtab->sh_entsize != 0) {
        const auto* strtab{file + shdrs[symtab->sh_link].sh_offset};
        const auto* syms{reinterpret_cast<const ElfW(Sym)*>(file + symtab->sh_offset)};
        const std::size_t count{symtab->sh_size / symtab->sh_entsize};
        for (std::size_t i = 0; i < count; ++i) {
            if (ELF64_ST_TYPE(syms[i].st_info) != STT_OBJECT) continue;
            if (syms[i].st_value == 0 || syms[i].st_size == 0) continue;
            g_symbols.push_back({g_main_base + syms[i].st_value,
                                 static_cast<std::size_t>(syms[i].st_size),
                                 strtab + syms[i].st_name});
        }
    }
    munmap(map, file_size);
    std::sort(g_symbols.begin(), g_symbols.end(),
              [](const Symbol& a, const Symbol& b) { return a.addr < b.addr; });
}

//! The symbol whose [addr, addr+size) contains p, or nullptr.
const Symbol* FindSymbol(const std::byte* p)
{
    const auto it{std::upper_bound(g_symbols.begin(), g_symbols.end(), p,
                                   [](const std::byte* a, const Symbol& s) { return a < s.addr; })};
    if (it == g_symbols.begin()) return nullptr;
    const Symbol& sym{*(it - 1)};
    return (p < sym.addr + sym.size) ? &sym : nullptr;
}

//! Globals that legitimately change every input because CheckGlobals manages
//! them and resets them at the start of the next iteration: its PRNG and
//! system-time usage flags, plus the mockable NodeClock value a target may set.
//! "g_mock_time" does not match "g_mock_steady_time", which is deliberately left
//! to be reported (the steady clock is not reset between iterations, see #35478).
bool IsExpectedChurn(std::string_view name)
{
    for (const std::string_view managed : {
             "g_used_g_prng", "g_seeded_g_prng_zero", "g_used_system_time",
             "g_mock_time"}) {
        if (name.find(managed) != std::string_view::npos) return true;
    }
    return false;
}

void Snapshot()
{
    for (auto& region : g_regions) {
        region.baseline.assign(region.addr, region.addr + region.len);
    }
}

void ReportRegion(const Region& region)
{
    std::size_t i{0};
    while (i < region.len) {
        if (region.addr[i] == region.baseline[i]) {
            ++i;
            continue;
        }
        const std::size_t start{i};
        while (i < region.len && region.addr[i] != region.baseline[i]) ++i;
        const std::byte* addr{region.addr + start};
        const Symbol* sym{FindSymbol(addr)};
        if (sym != nullptr && IsExpectedChurn(sym->name)) continue;
        std::fprintf(stderr, "[global-state] CHANGE %p len=%zu sym=%s\n",
                     static_cast<const void*>(addr), i - start,
                     sym != nullptr ? sym->name.c_str() : "?");
    }
}

bool g_initialized{false};

void Init()
{
    g_regions.clear();
    g_symbols.clear();
    dl_iterate_phdr(CollectCallback, nullptr);
    LoadMainSymbols();
    Snapshot();
}

} // namespace

void BeforeInput()
{
    if (!g_initialized) {
        g_initialized = true;
        Init();
    } else {
        Snapshot();
    }
}

void Check()
{
    for (const auto& region : g_regions) {
        if (std::memcmp(region.addr, region.baseline.data(), region.len) != 0) {
            ReportRegion(region);
        }
    }
}

} // namespace global_state
