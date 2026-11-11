# Liberator

Liberator moves an OpenCore PC with an NVIDIA card from macOS 15 or 26 to macOS 27, and sets up the NullMoth NVIDIA
driver there. It is a Mac app with one main button: **Prepare for Golden Gate**.

This is a beta. macOS 27 has been started this way on one desktop PC: an Intel processor with an RTX 50-series card.
Other boards, AMD processors and laptops are untried.

- Changes: [CHANGELOG.md](CHANGELOG.md)
- NVIDIA driver for macOS 15 and 26: [nvidia-macos-driver](https://github.com/nullmoth/nvidia-macos-driver)
- Building the first macOS install on a PC: [1401](https://github.com/nullmoth/1401)

## What you need

- A PC that already runs macOS 15 or macOS 26 through OpenCore, with the NullMoth NVIDIA driver working.
- About 102 GB free on the macOS disk for a first run. About 27 GB of that is downloads, most of it macOS 27 from Apple.
- A wired network connection. Wi-Fi and Bluetooth do not work on macOS 27 yet.
- About 30 minutes, plus the download.
- A backup of anything you cannot lose.

## Using it

1. Open Liberator on macOS 15 or 26.
2. Leave **Set up as a new Mac instead** unticked to bring your account over (name, password, administrator rights;
   not the files in your home folder). Tick it to start at Apple's setup instead.
3. Press **Prepare for Golden Gate** and confirm once. Liberator checks the PC, downloads what it needs, builds the
   startup files macOS 27 needs on this PC, puts macOS 27 on its own new volumes beside your current macOS, sets it
   up, and makes macOS 27 the default at startup.
4. When it says it is done, restart. The start text pauses at "PCI configuration" for up to two minutes. Wait.

If it stops part-way, press the button again. Steps that finished are not repeated and the downloads are kept.

## Going back

Your current macOS is not changed. In the OpenCore boot picker choose your macOS 15 or 26 disk, open Liberator
there, and press **Cancel Golden Gate** to put the old startup files back, or **Remove macOS 27** to also erase the
macOS 27 volumes Liberator made.

## Known limits of this beta

- No Wi-Fi and no Bluetooth on macOS 27.
- Books, Journal, Maps, Reminders and Voice Memos do not work yet.
- The Dock and other glass surfaces can look flat and dark.
- A run that fails after the system copy can leave one extra volume named "Macintosh HD" in the same container.
  Delete it in Disk Utility before the next try.

## If something goes wrong

Start your macOS 15 or 26 from the boot picker and press **Send a report** in Liberator. It can read the macOS 27
logs from there, so this works when macOS 27 never reached its desktop. Quote the report ID when you ask for help.

## Licence

See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).
