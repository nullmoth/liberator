# What is in this tree

Liberator is one app for PCs and Macs. It reads the hardware it runs on and builds the matching macOS 27 setup
(Golden Gate). Everything it installs is built from this tree, or downloaded from Apple and NVIDIA on the user's own
machine; no Apple or NVIDIA file is part of it.

| folder | what it is |
|---|---|
| `mac/` | the macOS app, its setup scripts (`Resources/nullmoth-setup.sh`, `Resources/nullmoth-golden-gate.sh`) and tests |
| `kit/` | the macOS 27 kit's installers: lay-down and kernel-collection scripts, the driver, built-in-graphics and Mac Pro packages, the system package and its start-up helpers. `kit/v3-kit.json` is the kit's manifest |
| `source/interp` | the interpreter that runs macOS 27's Apple-silicon programs on Intel |
| `source/translator` | the ahead-of-time translator the interpreter's tables are built from |
| `source/sandbox` | the Sandbox policy for macOS 27 on Intel (macOS 27 ships none for Intel) |
| `stock27/` | stock macOS 27 support: the exec-hook kernel extension source (`hook/`, built with its own `Makefile`, with an in-source `-DA2X_SELFTEST` harness), the keepalive start-up script, and the system-volume update payload. See `stock27/README.md` |
| `realmac27/` | real Mac support (Mac Pro, Late 2013): the platform driver used on PCs and Macs, the HD Audio driver, the AMD shader-compiler hook and helper tools. See `realmac27/README.md` |
| `upstream/` | third-party projects used as they are, each under its own licence |

The kernel collections are rebuilt on the user's machine from Apple's Kernel Debug Kit for macOS 27.2 (26B123) and
the patch files in the kit. The AMD graphics drivers on a Mac Pro are copied from that Mac's own macOS Tahoe.
