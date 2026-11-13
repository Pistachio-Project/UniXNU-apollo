# Device agent guide

This repository owns the apollo board DTS, peripheral wiring, component selections,
firmware inputs, partition layout, packaging, and its OS profiles until they are upstream in
UniXNU. On branch `ios27` the target is iOS 27.0.1 (24A446) on xnu-12377.121.6, rewritten for CPUs
without pointer authentication; `main` holds the iOS 16.5 port.

## Read first

| Task | Required reading |
| --- | --- |
| Every change | This README, `porting.toml`, [Porting](https://unixnu.com/porting/), [device repository](https://unixnu.com/porting/device-repository), [component catalog](https://unixnu.com/reference/components) |
| Hardware | [Device tree](https://unixnu.com/porting/device-tree), UniXNU-sm8250-common README, AGENTS and `dts/sm8250.dtsi` |
| Kernel | [Source and patches](https://unixnu.com/xnu/source-and-patches), [arm64e profiles](https://unixnu.com/porting/arm64e), `os-profiles/ios-27.0.1-24A446/`, `patches/xnu-12377/series`, porting.toml area `arm64e-nopac` |
| Images | [Prelink](https://unixnu.com/concepts/prelink), [payload](https://unixnu.com/concepts/payload), [UEFI](https://unixnu.com/porting/uefi-firmware), uefi-apollo README |
| Verification | [Building](https://unixnu.com/building), [bring-up](https://unixnu.com/porting/bring-up), [log capture](https://unixnu.com/porting/log-capture) |

## Rules

- Hardware values come from this phone: the uefi-apollo memory map, the phone's device tree,
  or a HakiOS driver that drives it. Name the source in a comment.
- SoC-wide resources and operations go to UniXNU-sm8250-common; reusable drivers go to
  component repositories. The HakiOS drivers in `patches/xnu/0001` move out one at a time
  (porting.toml lists each destination).
- The kernel is xnu-12377.121.6 on this branch (xnu-8796.121.2 on `main`); state the XNU version
  every patch was checked on. A change to the no-PAC patches or to `package/pacstrip` must leave
  `cd package/pacstrip && python3 -m unittest` passing (it compiles the C sources out of the patches).
- Never run two `./unixnu` commands at once on one output tree: each reassembles the build tree.
- No iOS files and no firmware in git. Firmware goes in `.cache/firmware` and
  `proprietary-files.txt` records its source and hash.
- Every code change updates the owning `porting.toml` area's findings or evidence. Host and
  device results are separate evidence entries with the full commit.
- Keep the license of each directory (NOTICE): APSL for `patches/xnu`, MIT for HakiOS
  scripts and `package/`, BSD-2-Clause-Patent for new files.

## Commands

```sh
scripts/install-os-profile.sh
cd ../UniXNU
./unixnu defconfig apollo_defconfig -D ../UniXNU-apollo
./unixnu status --json -D ../UniXNU-apollo
python3 scripts/porting-record.py check --device ../UniXNU-apollo
```

Report commands, revisions, output paths, results and unresolved inputs. Report boot,
storage, display, input, GPU, network, audio and power results separately.
