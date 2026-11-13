# UniXNU-apollo

UniXNU device repository for the Xiaomi Mi 10T / Mi 10T Pro / Redmi K30S Ultra (`apollo`,
Qualcomm SM8250).

**Branch `ios27`: iOS 27.0.1 (24A446).** iOS 27 is arm64e only and the SM8250's Cortex-A77/A55 have no
pointer authentication. This branch builds the arm64e kernel with Apple's 24A446 kexts on Linux, rewrites
it for these CPUs ([package/pacstrip](package/pacstrip), from
[darwin-lisa](https://github.com/mateusseiboth/darwin-lisa)) and boots it on the phone from RAM.

Status: **the kernel boots as far as `machine_lockdown`; no root volume and no user space yet.** The porting
record ([porting.toml](porting.toml)) is the authoritative statement of what is measured, what is planned
and what is blocked; start with its areas `arm64e-nopac`, `packaging` and `diagnostics`. The iOS 16.5 port
from [HakiOS](https://github.com/oosexgang/hackios-xnu-kernel) is on `main`.

| Repository | Role |
| --- | --- |
| [UniXNU](https://github.com/UniXNU/UniXNU) | Build tools, components, ARM64 profile |
| [UniXNU-sm8250-common](https://github.com/Pistachio-Project/UniXNU-sm8250-common) | Shared SM8250 DTSI, config and patches |
| [uefi-apollo](https://github.com/Pistachio-Project/uefi-apollo) | Mu-Silicium firmware with apolloPkg, UniXNU and DarwinBoot |
| this repository | Board DTS, components, firmware list, iOS 16.5 profile, HakiOS driver patches |

## Layout

| Path | Contents |
| --- | --- |
| `board.toml` | Board, SoC, OS profile, components, firmware, payload |
| `feeds.toml` | Pinned SoC source and XNU 8796.121.2 |
| `configs/apollo_defconfig` | Kernel configuration |
| `dts/apollo.dts` | Memory, reserved regions, CPUs, board wiring notes |
| `os-profiles/ios-27.0.1-24A446/` | iOS 27.0.1 OS profile (iPhone13,1 user space, the 24A446 kernelcache UniXNU's iPadOS 27 profile is pinned to) |
| `os-profiles/ios-16.5-20F66/` | iOS 16.5 OS profile (branch `main`) |
| `patches/xnu-12377/` | The iOS 27 kernel series: UniXNU-sheng's device series (`sheng/`), the no-PAC patches, the boot log |
| `patches/unixnu/` | Changes to UniXNU's Linux kernel step, applied by `scripts/apply-unixnu-patches.sh` |
| `patches/xnu/` | HakiOS's apollo drivers and hooks for xnu-8796, carried but not in any series |
| `package/` | `pacstrip/` (the arm64e rewrite and its tests), `prelink/` (pairing through two references), `aea/` (AEA decryption on Linux), HakiOS's ath11k glue and boot jobs |
| `scripts/` | Firmware pull, partition carving, mic calibration, touch firmware, packaging |
| `proprietary-files.txt` | The phone's firmware: path, source, SHA-256, consumer |

## Build

Siblings in one directory: `UniXNU`, `UniXNU-apollo`, `UniXNU-sm8250-common`, `uefi-apollo` (the last two
on their `ios27` branches). Host: Linux with UniXNU's toolchain (`scripts/linux/setup-toolchain.py`),
`dtc`, 7-Zip, OpenSSL 3.2 or later, and `llvm-lto` built from the toolchain's LLVM commit (for the
reference kernel; `UNIXNU_LLVM_LTO`).

```sh
scripts/apply-unixnu-patches.sh      # UniXNU's Linux kernel step for an arm64e profile (patches/unixnu)
scripts/install-os-profile.sh        # links os-profiles/ into ../UniXNU/profiles/os/
scripts/fetch-kernelcache.sh         # the 24A446 kernelcache the kexts come from
cd ../UniXNU
./unixnu defconfig apollo_defconfig -D ../UniXNU-apollo
./unixnu fetch && ./unixnu ipsw fetch
python3 scripts/bundle-ipsw-trust.py out/ipsw/24A446/trustcache-iphone13.bundle \
  out/ipsw/24A446/043-68873-661.dmg.aea.trustcache out/ipsw/24A446/043-69370-711.dmg.aea.trustcache
../UniXNU-apollo/scripts/build-kernel.sh   # kernel, pairing, prelink, rewrite for CPUs without PAC
./unixnu build package && ./unixnu build firmware --uefi ../uefi-apollo --target RELEASE
./unixnu payload --trust-cache out/ipsw/24A446/trustcache-iphone13.bundle --unique-chip-id HEX
./unixnu bootimg --dtb ../uefi-apollo/Resources/DTBs/apollo.dtb
../UniXNU-apollo/scripts/bootcycle.sh      # boots it from RAM and saves the kernel's console
```

The first `build-kernel.sh` needs UniXNU's RELEASE reference kernel once: uncomment the `#REF` line of
`board.toml` `[kernel] archives` for that run. Nothing is written to the phone's storage by any of this.

## Read

[Port a device](https://unixnu.com/porting/), [migration](https://unixnu.com/porting/migration),
[device repository](https://unixnu.com/porting/device-repository),
[device tree](https://unixnu.com/porting/device-tree), [records](https://unixnu.com/porting/records).

Licenses by directory: see [NOTICE](NOTICE).
