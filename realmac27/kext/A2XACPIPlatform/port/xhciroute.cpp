// xhciroute.cpp - give the USB ports of Intel 7/8/9-series and X99 chipsets to the xHCI controller.
//
// On these chipsets every port starts out routed to the EHCI controllers; the operating system's xHCI driver moves
// them (Linux: usb_enable_intel_xhci_ports, in pci-quirks.c). macOS 27 has no EHCI driver at all and its xHCI driver
// does not move them, so the xHCI controller attaches with every port-status 0 and no keyboard or mouse works
// (users on an X99 Dell T5810 and a 4th-generation desktop, Beta 4/5; an SSDT writing the same registers fixed it).
// The fix is the same two writes Linux makes, with the masks the chip reports:
//   USB3_PSSEN (0xD8) <- USB3PRM (0xDC): enable the SuperSpeed side of each port
//   XUSB2PR    (0xD0) <- XUSB2PRM (0xD4): route each USB 2 port to xHCI
// Only for those chipsets' xHCI functions (vendor 8086, class 0c0330). The writes are made from a thread call, not
// inside the nub's publish (a config write there once hung every PCI publish behind it, see vtdmap.cpp).
// Boot-arg a2x_xhciroute=0 turns it off.
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <kern/thread_call.h>
#include <pexpert/pexpert.h>

static const uint16_t kSwitchable[] = {
    0x1E31,   // 7-series (Panther Point)
    0x8C31,   // 8-series (Lynx Point)
    0x9C31,   // 8-series LP
    0x8CB1,   // 9-series (Wildcat Point)
    0x9CB1,   // 9-series LP
    0x8D31,   // C610 / X99 (Wellsburg)
};

static void A2XXHCIRouteNow(thread_call_param_t p0, thread_call_param_t)
{
    IOPCIDevice *d = (IOPCIDevice *)p0;
    uint32_t pssen0 = d->configRead32(0xD8), prm3 = d->configRead32(0xDC);
    uint32_t pr0 = d->configRead32(0xD0), prm2 = d->configRead32(0xD4);
    d->configWrite32(0xD8, prm3);
    d->configWrite32(0xD0, prm2);
    IOLog("ACPI: xHCI %x:%x.%x: ports to xHCI - USB3 enable %08x -> %08x (mask %08x), USB2 route %08x -> %08x (mask %08x)\n",
          d->getBusNumber(), d->getDeviceNumber(), d->getFunctionNumber(), pssen0, d->configRead32(0xD8), prm3,
          pr0, d->configRead32(0xD0), prm2);
    d->release();
}

static bool A2XXHCIPublished(void *, void *, IOService *svc, IONotifier *)
{
    IOPCIDevice *d = OSDynamicCast(IOPCIDevice, svc);
    if (!d) return true;
    uint32_t id = d->configRead32(kIOPCIConfigVendorID);
    if ((id & 0xFFFF) != 0x8086) return true;
    if ((d->configRead32(kIOPCIConfigRevisionID) >> 8) != 0x0c0330) return true;
    bool sw = false;
    for (unsigned i = 0; i < sizeof kSwitchable / sizeof kSwitchable[0]; i++) if ((id >> 16) == kSwitchable[i]) sw = true;
    if (!sw) return true;
    // one call per controller, once per boot: the thread call itself is not freed (a few bytes)
    thread_call_t tc = thread_call_allocate(A2XXHCIRouteNow, d);
    if (!tc) { IOLog("ACPI: xHCI port routing: no thread call\n"); return true; }
    d->retain();
    thread_call_enter(tc);
    return true;
}

void A2XXHCIRouteStart(void)
{
    UInt32 on = 1;
    PE_parse_boot_argn("a2x_xhciroute", &on, sizeof on);
    if (!on) { IOLog("ACPI: xHCI port routing off (a2x_xhciroute=0)\n"); return; }
    if (!IOService::addMatchingNotification(gIOFirstPublishNotification, IOService::serviceMatching("IOPCIDevice"),
                                            A2XXHCIPublished, NULL, NULL, 1000))
        IOLog("ACPI: xHCI port routing: no PCI publish notification\n");
}
