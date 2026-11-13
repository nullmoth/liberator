# Liberator Beta 2

Liberator moves an OpenCore PC that runs macOS 15 or macOS 26 to macOS 27.2 with one button, **Prepare for Golden Gate**. Beta 2 is a larger step than Beta 1: it fixes what the first reports found and opens the door to more kinds of PC.

## What is new

- Updating from Beta 1 works. Press **Prepare for Golden Gate** again and Liberator renews the macOS 27 startup files it made earlier, from macOS 26 or from macOS 27 itself, instead of stopping.
- Finished steps are no longer repeated. The kernel collections are not rebuilt when nothing changed, and no download room is asked for when macOS 27 is already on its own volumes.
- A Mac or PC whose disk and network controller macOS 27 read as external now reads them as built in. Features that check for an internal disk and a built-in network port can work.
- Start-up settings meant for debugging are no longer sent to your PC. Your boot arguments come out clean.
- Send a report now includes the macOS 27 logs in one piece. In Beta 1 a duplicated file made the report fail, so no macOS 27 logs reached us.
- The room Liberator asks for is smaller: about 92 GB free instead of about 102 GB.
- A Drivers step lists the extra drivers for macOS 27, lets you turn each one off, and keeps your choices.
- More kinds of PC are open for testing: AMD processors, other wired network chips, laptop keyboards and trackpads, and PCs with only built-in graphics. These are built but untried on real hardware, so please send a report either way.
- Programs built for Apple silicon: more of them start, including programs that keep their libraries inside themselves and programs built for macOS 11 or earlier.

## What you need

- macOS 15 or macOS 26 running through OpenCore, with the NullMoth NVIDIA driver working
- about 92 GB free on the macOS disk
- a wired network connection
- a backup of anything you cannot lose

## Updating from Beta 1

Download `@APP_ZIP@`, open it, and press **Prepare for Golden Gate**. Your macOS 27 volumes are kept. Beta 1 cannot update itself to Beta 2, so this one download is by hand.

## Known problems

- No Wi-Fi yet on macOS 27
- Bluetooth does not pair yet
- Apple Intelligence and Siri are not available
- Browsers and other programs that write their own machine code while running do not work yet
- Spotlight search does not work
- App Store apps are untested
- Real Intel Macs are not supported yet

## Files

| File | Size | SHA-256 |
|---|---|---|
| `@APP_ZIP@` | @APP_SIZE@ | `@APP_SHA@` |
| `@KIT_NAME@` | @KIT_SIZE@ | `@KIT_SHA@` |

Liberator downloads the second file itself and checks it against the SHA-256 it was built with. If the download fails, choose **Use a file I already downloaded** in the app.

## If something goes wrong

Start your macOS 15 or 26 from the boot picker and press **Send a report** in Liberator. Quote the report ID when you ask for help.

Liberator is free. Donations help keep the work going: nullmothsystems.com/donate
