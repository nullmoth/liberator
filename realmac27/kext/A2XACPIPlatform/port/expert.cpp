// SPDX-License-Identifier: BSD-3-Clause
//
// expert.cpp - ACPI platform expert for x86_64 Macs on macOS 27.
//
// Subclasses Apple's IOACPIPlatformExpert (IOACPIFamily, public SDK headers) and implements its contract on top of
// ACPICA. Device nubs are Apple's own IOACPIPlatformDevice class; their handle is the ACPICA namespace node.
//
// Planes, as the platform has always presented them:
//   IOACPIPlane    the ACPI namespace hierarchy (root nub -> \_SB -> PCI0 -> LPC -> RTC ...)
//   IOService      every registered nub flat under the expert, so drivers match on name/compatible
//
// IOACPIPlatformDevice::getResources() forwards to IOPlatformExpert::getNubResources(); this class builds each
// nub's IODeviceMemory and interrupt specifiers there, from _CRS and the MADT.

#include <IOKit/IOLib.h>
#include "crumb.h"
#include "confollow.h"
static struct cf_state gCF;      // console-follow policy state (setConsoleInfo below)
static IOLock         *gCFLock;  // two configurator work loops can call setConsoleInfo at once
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/acpi/IOACPIPlatformExpert.h>
#include <IOKit/acpi/IOACPIPlatformDevice.h>
#include <IOKit/rtc/IORTCController.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSString.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSDictionary.h>
#include <IOKit/IOCatalogue.h>
#include <architecture/i386/pio.h>
#include "events.h"
#include "cpuint.h"
#include "devprops.h"
#include <kern/thread.h>
#include <IOKit/pwr_mgt/RootDomain.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOBufferMemoryDescriptor.h>

// Boot diagnostic (boot-arg a2xreadprobe=1): at 60, 120 and 180 s read block 0 of every whole IOMedia and log
// the IOReturn and each layer's power state, so a disk whose partition probe fails shows why its reads fail.
static void A2XReadProbe(void *, wait_result_t)
{
    static const unsigned marks[] = { 60, 120, 180 };
    unsigned prev = 0;
    for (unsigned i = 0; i < sizeof marks / sizeof marks[0]; i++) {
        IOSleep((marks[i] - prev) * 1000); prev = marks[i];
        OSIterator *it = IOService::getMatchingServices(IOService::serviceMatching("IOMedia"));
        if (!it) { IOLog("ACPI: readprobe t=%u no IOMedia iterator\n", marks[i]); continue; }
        unsigned n = 0;
        while (OSObject *o = it->getNextObject()) {
            // String metaCast: no IOMedia::metaClass import (this kext does not link IOStorageFamily).
            IOMedia *m = (o && o->metaCast("IOMedia")) ? (IOMedia *)o : NULL;
            if (!m || !m->isWhole()) continue;
            n++;
            UInt64 bs = m->getPreferredBlockSize(); if (!bs || bs > 65536) bs = 512;
            IOLog("ACPI: readprobe t=%u %s size %llu bs %llu busy %u open %u\n", marks[i], m->getName(),
                  m->getSize(), bs, m->getBusyState(), m->isOpen(NULL) ? 1 : 0);
            for (IORegistryEntry *p = m->getParentEntry(gIOServicePlane); p; p = p->getParentEntry(gIOServicePlane)) {
                IOService *s = OSDynamicCast(IOService, p); if (!s) break;
                IOLog("ACPI: readprobe   up %s (%s) pm %lu busy %u%s\n", s->getName(), s->getMetaClass()->getClassName(),
                      s->getPowerState(), s->getBusyState(), s->isInactive() ? " inactive" : "");
                if (!strcmp(s->getMetaClass()->getClassName(), "AppleAHCI")) break;
            }
            IOBufferMemoryDescriptor *b = IOBufferMemoryDescriptor::withCapacity(bs, kIODirectionIn);
            if (!b) { IOLog("ACPI: readprobe   no buffer\n"); continue; }
            if (!m->open(m, 0, kIOStorageAccessReader)) {
                IOLog("ACPI: readprobe   open as reader refused\n");
            } else {
                UInt64 actual = 0;
                uint64_t t0 = mach_absolute_time(), ns;
                IOReturn r = m->read(m, 0, b, NULL, &actual);
                absolutetime_to_nanoseconds(mach_absolute_time() - t0, &ns);
                const UInt8 *d = (const UInt8 *)b->getBytesNoCopy();
                IOLog("ACPI: readprobe   read lba0 -> 0x%x actual %llu in %llu us, bytes 1fe=%02x%02x\n",
                      r, actual, ns / 1000, d[0x1fe], d[0x1ff]);
                m->close(m, kIOStorageAccessReader);
            }
            b->release();
        }
        it->release();
        IOLog("ACPI: readprobe t=%u whole media %u\n", marks[i], n);
    }
}

// Boot diagnostic: 60 s after the platform starts, name every service still busy (matching or starting) and
// everything attached to the RTC nub, so a stalled boot shows which driver it waits on.
void A2XDumpVectorCounts(void);
static void A2XBusyDumpOnce(unsigned secs);
// VT-d register windows mapped by a2xVTdTranslationOff, kept so the heartbeat can show their status.
static volatile UInt32 *gA2XVTdRegs[8];
static UInt64 gA2XVTdBase[8];
static UInt32 gA2XVTdCount;
// One line per storage (class 01), network (02) and USB (0c03) function: who drives it and whether it can interrupt.
void A2XVTdReport(void);   // vtdmap.cpp
// Legacy interrupt lines held asserted (PCI Status bit 3). Display functions (class 03) whose only client is the
// firmware framebuffer, or none, cannot service INTx, so their line is disabled at the device (Command bit 10).
static void A2XINTxGuard(void)
{
    OSDictionary *m = IOService::serviceMatching("IOPCIDevice");
    OSIterator *it = m ? IOService::getMatchingServices(m) : NULL;
    if (m) m->release();
    if (!it) return;
    IOService *o;
    while ((o = OSDynamicCast(IOService, it->getNextObject()))) {
        IOPCIDevice *d = OSDynamicCast(IOPCIDevice, o);
        if (!d) continue;
        UInt16 st = d->configRead16(kIOPCIConfigStatus), cmd = d->configRead16(kIOPCIConfigCommand);
        if (!(st & (1u << 3)) || (cmd & (1u << 10))) continue;            // not asserting, or already disabled
        UInt32 cls = d->configRead32(kIOPCIConfigRevisionID) >> 8;
        OSIterator *ci = d->getClientIterator();
        const char *drv = "-";
        if (ci) { IOService *c = OSDynamicCast(IOService, ci->getNextObject()); if (c) drv = c->getMetaClass()->getClassName(); ci->release(); }
        bool display = (cls >> 16) == 0x03;
        bool noDriver = !strcmp(drv, "-") || !strcmp(drv, "IONDRVFramebuffer") || !strcmp(drv, "IOFramebuffer");
        if (display && noDriver) d->configWrite16(kIOPCIConfigCommand, (UInt16)(cmd | (1u << 10)));
        IOLog("ACPI:   intx asserted %x:%x.%x cls %06x drv %s%s\n", d->getBusNumber(), d->getDeviceNumber(),
              d->getFunctionNumber(), cls, drv, (display && noDriver) ? " -> line disabled at the device" : "");
    }
    it->release();
}
static void A2XDumpPCIFacts(void)
{
    A2XINTxGuard();
    A2XVTdReport();
    for (UInt32 u = 0; u < gA2XVTdCount; u++)
        IOLog("ACPI:   vtd 0x%llx gsts 0x%08x\n", gA2XVTdBase[u], (unsigned)gA2XVTdRegs[u][0x1C / 4]);
    OSDictionary *m = IOService::serviceMatching("IOPCIDevice");
    OSIterator *it = m ? IOService::getMatchingServices(m) : NULL;
    if (m) m->release();
    if (!it) return;
    IOService *o; int n = 0;
    while ((o = OSDynamicCast(IOService, it->getNextObject())) && n < 14) {
        IOPCIDevice *d = OSDynamicCast(IOPCIDevice, o);
        if (!d) continue;
        UInt32 cls = d->configRead32(kIOPCIConfigRevisionID) >> 8;
        UInt32 base = cls >> 16, sub = (cls >> 8) & 0xff;
        if (!(base == 0x01 || base == 0x02 || (base == 0x0c && sub == 0x03))) continue;
        UInt32 id = d->configRead32(kIOPCIConfigVendorID);
        UInt16 cmd = d->configRead16(kIOPCIConfigCommand);
        UInt32 bar0 = d->configRead32(kIOPCIConfigBaseAddress0);
        IOByteCount off = 0; int msi = -1, msix = -1;
        if (d->extendedFindPCICapability(kIOPCICapabilityIDMSI, &off) && off)  msi  = (d->configRead16(off + 2) & 1) ? 1 : 0;
        off = 0;
        if (d->extendedFindPCICapability(kIOPCICapabilityIDMSIX, &off) && off) msix = (d->configRead16(off + 2) & 0x8000) ? 1 : 0;
        OSIterator *ci = d->getClientIterator();
        const char *drv = "-";
        if (ci) { IOService *c = OSDynamicCast(IOService, ci->getNextObject()); if (c) drv = c->getMetaClass()->getClassName(); ci->release(); }
        IOLog("ACPI:   pci %x:%x.%x %04x:%04x cls %06x drv %s bar0 0x%08x cmd 0x%04x msi %d msix %d busy %u\n",
              d->getBusNumber(), d->getDeviceNumber(), d->getFunctionNumber(), id & 0xffff, id >> 16, cls, drv,
              (unsigned)bar0, cmd, msi, msix, (unsigned)d->getBusyState());
        n++;
    }
    it->release();
}
// Display functions (class 03) and the bridge above each: command, status (bit 3 = INTx asserted), and the MSI
// capability as the device holds it (control: bit 0 enable, bit 7 64-bit, bit 8 per-vector mask).
static void A2XDumpGPUFacts(void)
{
    OSDictionary *m = IOService::serviceMatching("IOPCIDevice");
    OSIterator *it = m ? IOService::getMatchingServices(m) : NULL;
    if (m) m->release();
    if (!it) return;
    IOService *o;
    while ((o = OSDynamicCast(IOService, it->getNextObject()))) {
        IOPCIDevice *d = OSDynamicCast(IOPCIDevice, o);
        if (!d) continue;
        UInt32 cls = d->configRead32(kIOPCIConfigRevisionID) >> 8;
        if ((cls >> 16) != 0x03) continue;
        for (int lvl = 0; lvl < 2 && d; lvl++) {
            UInt16 cmd = d->configRead16(kIOPCIConfigCommand), st = d->configRead16(kIOPCIConfigStatus);
            IOByteCount off = 0;
            UInt16 ctl = 0; UInt32 lo = 0, hi = 0, data = 0, mask = 0, pend = 0;
            bool has = d->extendedFindPCICapability(kIOPCICapabilityIDMSI, &off) && off;
            if (has) {
                ctl = d->configRead16(off + 2);
                lo  = d->configRead32(off + 4);
                bool b64 = ctl & 0x80;
                if (b64) hi = d->configRead32(off + 8);
                data = d->configRead16(off + (b64 ? 0xC : 0x8));
                if (ctl & 0x100) { mask = d->configRead32(off + (b64 ? 0x10 : 0xC)); pend = d->configRead32(off + (b64 ? 0x14 : 0x10)); }
            }
            IOLog("ACPI:   gpu%s %x:%x.%x cmd 0x%04x st 0x%04x msi %s ctl 0x%04x addr 0x%08x%08x data 0x%04x mask 0x%x pend 0x%x\n",
                  lvl ? "-bridge" : "", d->getBusNumber(), d->getDeviceNumber(), d->getFunctionNumber(), cmd, st,
                  has ? "cap" : "none", ctl, (unsigned)hi, (unsigned)lo, (unsigned)data, (unsigned)mask, (unsigned)pend);
            IORegistryEntry *pe = d->getParentEntry(gIOServicePlane);      // the IOPCI2PCIBridge driver
            pe = pe ? pe->getParentEntry(gIOServicePlane) : NULL;            // its bridge nub
            d = OSDynamicCast(IOPCIDevice, pe);
        }
    }
    it->release();
}
void A2XStartDisplayKick(A2XCPUInterruptController *ctl, UInt32 msiDest);
static UInt32 gA2XDeadline;
static void A2XDeadline(void *, wait_result_t)
{
    for (UInt32 t = 0; t < gA2XDeadline; t += 10) IOSleep(10000);
    IOLog("ACPI: a2x_deadline %u s reached: panicking on purpose (proves log save + restart)\n", (unsigned)gA2XDeadline);
    IOSleep(1000);
    panic("A2X deadline %u s reached: deliberate panic, not a fault", (unsigned)gA2XDeadline);
}
static void A2XIHMonitor(void *, wait_result_t)
{
    IOPCIDevice *gpu[4] = { 0 };
    IOMemoryMap *map[4] = { 0 };
    UInt32 n = 0;
    for (unsigned t = 0; t < 900; t += 2) {
        IOSleep(2000);
        if (n == 0 && t < 400) {
            OSDictionary *m = IOService::serviceMatching("IOPCIDevice");
            OSIterator *it = m ? IOService::getMatchingServices(m) : NULL;
            if (m) m->release();
            IOService *o;
            while (it && n < 4 && (o = OSDynamicCast(IOService, it->getNextObject()))) {
                IOPCIDevice *d = OSDynamicCast(IOPCIDevice, o);
                if (!d || (d->configRead32(kIOPCIConfigRevisionID) >> 24) != 0x03) continue;
                IOMemoryMap *mm = d->mapDeviceMemoryWithRegister(kIOPCIConfigBaseAddress2);
                if (!mm) continue;
                if (mm->getLength() < 0x10000 || !(*(volatile UInt32 *)(mm->getVirtualAddress() + 0x3e00) & 1)) { mm->release(); continue; }
                d->retain(); gpu[n] = d; map[n] = mm; n++;
            }
            if (it) it->release();
            if (n) IOLog("ACPI: ih monitor: %u gpu(s) with the interrupt ring enabled\n", (unsigned)n);
        }
        for (UInt32 g = 0; g < n; g++) {
            volatile UInt8 *r = (volatile UInt8 *)map[g]->getVirtualAddress();
            #define RD(o) (*(volatile UInt32 *)(r + (o)))
            UInt32 rp[6], wp[6];
            for (int k = 0; k < 6; k++) { rp[k] = RD(0x3e08); wp[k] = RD(0x3e0c); IODelay(300); }
            IOLog("ACPI: ih %x:%x.%x t=%us cntl 0x%x ihcntl 0x%x base 0x%x wbaddr 0x%x rptr/wptr %x/%x %x/%x %x/%x %x/%x %x/%x %x/%x grbm 0x%08x srbm 0x%08x\n",
                  gpu[g]->getBusNumber(), gpu[g]->getDeviceNumber(), gpu[g]->getFunctionNumber(), t + 2,
                  (unsigned)RD(0x3e00), (unsigned)RD(0x3e18), (unsigned)RD(0x3e04), (unsigned)RD(0x3e14),
                  (unsigned)rp[0], (unsigned)wp[0], (unsigned)rp[1], (unsigned)wp[1], (unsigned)rp[2], (unsigned)wp[2],
                  (unsigned)rp[3], (unsigned)wp[3], (unsigned)rp[4], (unsigned)wp[4], (unsigned)rp[5], (unsigned)wp[5],
                  (unsigned)RD(0x8010), (unsigned)RD(0x0e50));
            #undef RD
        }
    }
    for (UInt32 g = 0; g < n; g++) { map[g]->release(); gpu[g]->release(); }
}
void A2XKickReport(void);
static UInt32 gA2XBusyMode;   // a2xbusydump value: 1 full, 2 compact
static void A2XBusyDump(void *, wait_result_t)
{
    static const unsigned marks[] = { 20, 40, 60, 90, 120, 180, 240, 300, 360, 420, 480, 600 };
    unsigned prev = 0;
    // Timer accuracy: AHCI's empty-port wait is 500 x IOSleep(1). Measure what one short sleep really costs here.
    {
        static const unsigned ms[] = { 1, 2, 10 };
        for (unsigned j = 0; j < 3; j++) {
            uint64_t t0 = mach_absolute_time(), ns;
            for (unsigned k = 0; k < 100; k++) IOSleep(ms[j]);
            absolutetime_to_nanoseconds(mach_absolute_time() - t0, &ns);
            IOLog("ACPI: timer 100 x IOSleep(%u) = %llu us (ideal %u us)\n", ms[j], ns / 1000, ms[j] * 100000);
        }
        uint64_t t0 = mach_absolute_time(), ns;
        for (unsigned k = 0; k < 1000; k++) IODelay(100);
        absolutetime_to_nanoseconds(mach_absolute_time() - t0, &ns);
        IOLog("ACPI: timer 1000 x IODelay(100) = %llu us (ideal 100000 us)\n", ns / 1000);
    }
    for (unsigned i = 0; i < sizeof marks / sizeof marks[0]; i++) {
        IOSleep((marks[i] - prev) * 1000);
        prev = marks[i];
        A2XBusyDumpOnce(marks[i]);
    }
}

// Prints the numeric IOPowerManagement fields (current, desired, max, child, driver states) of one service.
static void A2XDumpPM(const char *tag, IOService *s)
{
    OSDictionary *d = OSDynamicCast(OSDictionary, s->getProperty("IOPowerManagement"));
    if (!d) return;
    OSCollectionIterator *i = OSCollectionIterator::withCollection(d);
    if (!i) return;
    OSSymbol *k;
    while ((k = (OSSymbol *)i->getNextObject())) {
        OSNumber *v = OSDynamicCast(OSNumber, d->getObject(k));
        OSString *t = OSDynamicCast(OSString, d->getObject(k));
        if (v) IOLog("ACPI:   pm %s %s=%llu\n", tag, k->getCStringNoCopy(), v->unsigned64BitValue());
        else if (t) IOLog("ACPI:   pm %s %s=%s\n", tag, k->getCStringNoCopy(), t->getCStringNoCopy());
    }
    i->release();
}

static void A2XBusyDumpOnce(unsigned secs)
{
    if (gA2XBusyMode == 2) {
        uint32_t last = 0, seq = a2x_crumb_seq(&last);
        IOLog("ACPI: HEARTBEAT t=%us crumbs %u last 0x%08x\n", secs, seq, last);
        if (secs == 20 || secs == 60 || secs == 120) A2XDumpPCIFacts();
        A2XDumpVectorCounts();
        A2XDumpGPUFacts();
        A2XKickReport();
        IORegistryIterator *it = IORegistryIterator::iterateOver(gIOServicePlane, kIORegistryIterateRecursively);
        int n = 0;
        if (it) {
            IORegistryEntry *e;
            while ((e = it->getNextObject()) && n < 12) {
                IOService *s = OSDynamicCast(IOService, e);
                if (!s || !s->getBusyState()) continue;
                bool busyChild = false;
                OSIterator *ci = s->getClientIterator();
                if (ci) {
                    OSObject *o;
                    while ((o = ci->getNextObject())) {
                        IOService *c = OSDynamicCast(IOService, o);
                        if (c && c->getBusyState()) { busyChild = true; break; }
                    }
                    ci->release();
                }
                if (busyChild) continue;
                IORegistryEntry *pe = s->getParentEntry(gIOServicePlane);
                IOLog("ACPI:   stuck %s (%s) under %s busy %u%s\n", s->getName(), s->getMetaClass()->getClassName(),
                      pe ? pe->getName() : "-", s->getBusyState(), s->isInactive() ? " inactive" : "");
                n++;
            }
            it->release();
        }
        return;
    }
    IOLog("ACPI: t=%us\n", secs);
    {
        IOPMrootDomain *rd = IOService::getPMRootDomain();
        IOLog("ACPI: rootDomain %p pm %lu\n", rd, rd ? rd->getPowerState() : 0UL);
        if (rd) A2XDumpPM("rootDomain", rd);
    }
    A2XDumpVectorCounts();
    IORegistryIterator *it = IORegistryIterator::iterateOver(gIOServicePlane, kIORegistryIterateRecursively);
    int n = 0;
    if (it) {
        IORegistryEntry *e;
        while ((e = it->getNextObject())) {
            IOService *s = OSDynamicCast(IOService, e);
            if (!s) continue;
            bool rtc = !strcmp(s->getName(), "RTC_");
            if (s->getBusyState() && n < 80) {
                IORegistryEntry *pe = s->getParentEntry(gIOServicePlane);
                IOLog("ACPI: busy %u %s (%s) under %s%s pm %lu%s\n", s->getBusyState(), s->getName(),
                      s->getMetaClass()->getClassName(), pe ? pe->getName() : "-", s->isInactive() ? " inactive" : "",
                      s->getPowerState(), s->getProperty("IOPowerManagement") ? "" : " (no PM)");
                n++;
                A2XDumpPM(s->getName(), s);
                OSIterator *ci = s->getClientIterator();
                if (ci) {
                    OSObject *o;
                    while ((o = ci->getNextObject())) {
                        IOService *c = OSDynamicCast(IOService, o);
                        if (c && !c->getBusyState())
                            IOLog("ACPI:   client %s (%s)%s%s\n", c->getName(), c->getMetaClass()->getClassName(),
                                  c->isInactive() ? " inactive" : "", "");
                    }
                    ci->release();
                }
                // Which catalogue personality holds this nub busy: a passive match whose class is not loaded
                // is a module stall (xnu probeCandidates adds busy +1 until that module loads).
                SInt32 gen = 0;
                OSOrderedSet *drv = gIOCatalogue ? gIOCatalogue->findDrivers(s, &gen) : NULL;
                if (drv) {
                    OSObject *o; unsigned k = 0;
                    while ((o = drv->getObject(k++)) && k < 200) {
                        OSDictionary *pd = OSDynamicCast(OSDictionary, o);
                        if (!pd) continue;
                        OSString *b = OSDynamicCast(OSString, pd->getObject("CFBundleIdentifier"));
                        OSString *c = OSDynamicCast(OSString, pd->getObject("IOClass"));
                        const OSSymbol *cs = c ? OSSymbol::withString(c) : NULL;
                        const OSMetaClass *mc = cs ? OSMetaClass::getMetaClassWithName(cs) : NULL;
                        if (cs) cs->release();
                        OSString *pc = OSDynamicCast(OSString, pd->getObject("IOProviderClass"));
                        IOLog("ACPI:   cat %s class %s %s on %s%s\n", b ? b->getCStringNoCopy() : "-",
                              c ? c->getCStringNoCopy() : "-", mc ? "loaded" : "NOT-LOADED",
                              pc ? pc->getCStringNoCopy() : "-", pd->getObject("IOPropertyMatch") ? " +propmatch" : "");
                    }
                    drv->release();
                }
            }
            if (rtc && secs == 20) {
                OSIterator *ci = s->getClientIterator();
                if (ci) {
                    OSObject *o;
                    while ((o = ci->getNextObject())) {
                        IOService *c = OSDynamicCast(IOService, o);
                        if (c) IOLog("ACPI:   RTC_ client %s (%s) busy %u\n", c->getName(),
                                     c->getMetaClass()->getClassName(), c->getBusyState());
                    }
                    ci->release();
                }
            }
        }
        it->release();
    }
    IOLog("ACPI: busy dump done t=%us (%d)\n", secs, n);
}

// IOPCIFamily: creates the PCI message (MSI) controller, registers it with the platform and installs the
// VT-d driver from the DMAR table. The platform calls it once its CPU interrupt controller exists.
extern int IOPCIPlatformInitialize(void);

// Interrupt specifier = { u32 pin, u32 flags }, the I/O APIC driver's contract: pin is LOCAL to that I/O APIC
// (GSI - its GSI base); flags bit0 level, bit1 shareable (hint), bit2 active-low. This reproduces every value the
// platform has published: ISA edge/high = 0, SCI = 5, PCI INTx level/low/shared = 7.
enum : UInt32 {
    kA2XIntLevel     = 0x1,
    kA2XIntShareable = 0x2,
    kA2XIntActiveLow = 0x4,
};
#define kA2XIOAPICVectorLimit 0x70      // end of the I/O APIC vector window; MSI vectors start here (published 112)

#define kA2XMaxIOAPIC 8

class A2XACPIPlatformExpert : public IOACPIPlatformExpert
{
    OSDeclareDefaultStructors(A2XACPIPlatformExpert)

    struct IOAPICInfo { UInt32 id; UInt32 address; UInt32 gsiBase; };
    struct ISOverride { UInt8 present; UInt32 gsi; UInt16 flags; };

    IOAPICInfo     fIOAPIC[kA2XMaxIOAPIC];
    UInt32         fIOAPICCount;
    ISOverride     fISO[16];
    OSDictionary  *fTables;
    IOLock        *fLock;
    OSArray       *fSpaceHandlers;
    UInt32         fCPUIndex;
    OSArray       *fDeferredNubs;           // nubs registered after the whole namespace is published (nsorder)
    IOService     *fCPUNub[kA2XMaxCPUs];    // processor nub per processor-index (retained; nubs live as long as the platform)
    bool           fACPIReady;
    A2XACPIEventController *fEvents;
    A2XCPUInterruptController *fCPUInt;

    // events
    bool          startEvents(void);
    void          publishFixedButtons(void);
    void          appendEventSpecs(IOACPIPlatformDevice *dev, ACPI_HANDLE h, OSArray *specs, OSArray *ctrls);
    SInt32        addEventSpec(IOService *device, SInt64 vector);
    UInt32        sciGSI(UInt32 *flags) const;
    static void   notifyHandler(ACPI_HANDLE h, UINT32 value, void *ctx);

    // setup
    bool          initACPI(void);
    void          readMADT(void);
    void          publishNamespace(IOService *provider);
    void          publishChildren(ACPI_HANDLE parent, IORegistryEntry *acpiParent, IORegistryEntry *dtParent);
    IOACPIPlatformDevice *makeNub(ACPI_HANDLE h, ACPI_OBJECT_TYPE type, IORegistryEntry *acpiParent,
                                  IORegistryEntry *dtParent, bool *descend);
    IORegistryEntry *fDTRoot;       // the platform's device-tree root (our provider)
    IORegistryEntry *fDTCpus;       // IODeviceTree:/cpus, parent of the processor nubs in that plane
    void          publishIOAPICs(void);
    void          publishTables(void);

    // helpers
    static IOReturn  status(ACPI_STATUS s);
    static OSObject *toOS(const ACPI_OBJECT *o, int depth);
    static bool      fromOS(OSObject *in, ACPI_OBJECT *out, int depth);
    static void      freeParams(ACPI_OBJECT *objs, UInt32 count, int depth);
    UInt32           gsiForIsaIrq(UInt32 irq, UInt32 *flags) const;
    const OSSymbol  *controllerForGSI(UInt32 gsi) const;
    UInt32           pinForGSI(UInt32 gsi) const;
    IOReturn         resolvePCIInterrupt(IOService *bridge, UInt32 device, UInt32 pin, UInt32 *gsiOut);
    IOReturn         setDeviceInterrupts(IOService *nub, const UInt32 *vectors, UInt32 count, bool exclusive);
    UInt8            fPCIGSIFlags[256];      // flags | 0x80 for each GSI handed out by resolvePCIInterrupt
    UInt32           fBSPApicID;
    bool             fBSPFound;
    UInt32           fLapicID[kA2XMaxCPUs];  // every enabled processor in the MADT (types 0 and 9)
    UInt32           fLapicCount;
    UInt32           fProcUID[kA2XMaxCPUs];  // ACPI processor id of every enabled MADT processor
    UInt32           fProcUIDCount;

public:
    virtual bool     init(OSDictionary *dict) APPLE_KEXT_OVERRIDE;
    virtual void     free(void) APPLE_KEXT_OVERRIDE;
    virtual IOService *probe(IOService *provider, SInt32 *score) APPLE_KEXT_OVERRIDE;
    virtual bool     start(IOService *provider) APPLE_KEXT_OVERRIDE;
    virtual IOReturn getNubResources(IOService *nub) APPLE_KEXT_OVERRIDE;
    virtual void PMRegisterDevice(IOService *nub, IOService *device) APPLE_KEXT_OVERRIDE;
    virtual int      haltRestart(unsigned int type) APPLE_KEXT_OVERRIDE;
    virtual IOByteCount savePanicInfo(UInt8 *buffer, IOByteCount length) APPLE_KEXT_OVERRIDE;
    // EFI device-properties (OpenCore DeviceProperties) land on each IOPCIDevice here, before it matches.
    virtual bool     platformAdjustService(IOService *service) APPLE_KEXT_OVERRIDE;
    // The kernel calendar comes from these (PEGet/PESetUTCTimeOfDay); the base class returns 0 = 1970.
    virtual void     getUTCTimeOfDay(clock_sec_t *secs, clock_nsec_t *nsecs) APPLE_KEXT_OVERRIDE;
    virtual void     setUTCTimeOfDay(clock_sec_t secs, clock_nsec_t nsecs) APPLE_KEXT_OVERRIDE;
    virtual const char *deleteList(void) APPLE_KEXT_OVERRIDE;
    virtual const char *excludeList(void) APPLE_KEXT_OVERRIDE;
    virtual IOReturn registerInterruptController(OSSymbol *name, IOInterruptController *ctl) APPLE_KEXT_OVERRIDE;
    using IOACPIPlatformExpert::compareNubName;
    virtual bool     compareNubName(const IOService *nub, OSString *name, OSString **matched) const APPLE_KEXT_OVERRIDE;
    using IOACPIPlatformExpert::callPlatformFunction;
    virtual IOReturn setConsoleInfo(PE_Video *consoleInfo, unsigned int op) override;
    virtual IOReturn callPlatformFunction(const OSSymbol *functionName, bool waitForFunction, void *param1,
                                          void *param2, void *param3, void *param4) APPLE_KEXT_OVERRIDE;

protected:
    virtual SInt32   installDeviceInterruptForFixedEvent(IOService *device, UInt32 fixedEvent) APPLE_KEXT_OVERRIDE;
    virtual SInt32   installDeviceInterruptForGPE(IOService *device, UInt32 gpeNumber, void *gpeBlockDevice,
                                                  IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual IOReturn acquireGlobalLock(IOService *client, UInt32 *lockToken, const mach_timespec_t *timeout) APPLE_KEXT_OVERRIDE;
    virtual void     releaseGlobalLock(IOService *client, UInt32 lockToken) APPLE_KEXT_OVERRIDE;
    virtual IOReturn validateObject(IOACPIPlatformDevice *device, const OSSymbol *objectName) APPLE_KEXT_OVERRIDE;
    virtual IOReturn validateObject(IOACPIPlatformDevice *device, const char *objectName) APPLE_KEXT_OVERRIDE;
    virtual IOReturn evaluateObject(IOACPIPlatformDevice *device, const OSSymbol *objectName, OSObject **result,
                                    OSObject *params[], IOItemCount paramCount, IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual IOReturn evaluateObject(IOACPIPlatformDevice *device, const char *objectName, OSObject **result,
                                    OSObject *params[], IOItemCount paramCount, IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual const OSData *getACPITableData(const char *tableName, UInt32 tableInstance) APPLE_KEXT_OVERRIDE;
    virtual IOReturn registerAddressSpaceHandler(IOACPIPlatformDevice *device, IOACPIAddressSpaceID spaceID,
                                                 IOACPIAddressSpaceHandler handler, void *context,
                                                 IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual void     unregisterAddressSpaceHandler(IOACPIPlatformDevice *device, IOACPIAddressSpaceID spaceID,
                                                   IOACPIAddressSpaceHandler handler, IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual IOReturn readAddressSpace(UInt64 *value, IOACPIAddressSpaceID spaceID, IOACPIAddress address,
                                      UInt32 bitWidth, UInt32 bitOffset, IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual IOReturn writeAddressSpace(UInt64 value, IOACPIAddressSpaceID spaceID, IOACPIAddress address,
                                       UInt32 bitWidth, UInt32 bitOffset, IOOptionBits options) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setDevicePowerState(IOACPIPlatformDevice *device, UInt32 powerState) APPLE_KEXT_OVERRIDE;
    virtual IOReturn getDevicePowerState(IOACPIPlatformDevice *device, UInt32 *powerState) APPLE_KEXT_OVERRIDE;
    virtual IOReturn setDeviceWakeEnable(IOACPIPlatformDevice *device, bool enable) APPLE_KEXT_OVERRIDE;
};

OSDefineMetaClassAndStructors(A2XACPIPlatformExpert, IOACPIPlatformExpert)

// EFI device-properties state (platformAdjustService). The blob is COPIED (the /efi property could be replaced
// later) and parsed all-or-nothing. a2xDPState: 0 = not yet tried, 1 = ready, 2 = none or refused.
static IOLock       *a2xDPLock;
static uint8_t      *a2xDPBlob;
static size_t        a2xDPLen;
static a2x_dp_db    *a2xDP;
static volatile SInt32 a2xDPState;
static UInt32        a2xDPApplied, a2xDPSkipped, a2xDPDevices;
static UInt64        a2xDPHit;        // bit i = node i matched a device (A2X_DP_MAX_NODES == 64)

// ================================================================ lifecycle

bool A2XACPIPlatformExpert::init(OSDictionary *dict)
{
    if (!IOACPIPlatformExpert::init(dict)) return false;
    fIOAPICCount = 0;
    bzero(fIOAPIC, sizeof fIOAPIC);
    bzero(fISO, sizeof fISO);
    fBSPApicID = 0;
    fBSPFound = false;
    fLapicCount = 0;
    fProcUIDCount = 0;
    fTables = OSDictionary::withCapacity(16);
    fSpaceHandlers = OSArray::withCapacity(4);
    fLock = IOLockAlloc();
    if (!a2xDPLock) a2xDPLock = IOLockAlloc();   // device-properties; NULL = feature off, boot unchanged
    fCPUIndex = 0;
    fACPIReady = false;
    fDTRoot = NULL;
    fDTCpus = NULL;
    fEvents = NULL;
    fCPUInt = NULL;
    return fTables && fSpaceHandlers && fLock;
}

void A2XACPIPlatformExpert::free(void)
{
    OSSafeReleaseNULL(fTables);
    OSSafeReleaseNULL(fSpaceHandlers);
    OSSafeReleaseNULL(fEvents);
    if (fLock) { IOLockFree(fLock); fLock = NULL; }
    IOACPIPlatformExpert::free();
}

IOService *A2XACPIPlatformExpert::probe(IOService *provider, SInt32 *score)
{
    // Only claim a platform whose firmware actually publishes an RSDP.
    return AcpiOsGetRootPointer() ? this : NULL;
}

bool A2XACPIPlatformExpert::initACPI(void)
{
    ACPI_STATUS s;
    if (ACPI_FAILURE(s = AcpiInitializeSubsystem()))                 { IOLog("ACPI: subsystem init: %s\n", AcpiFormatException(s)); return false; }
    // _OSI as Apple answers it: Darwin only, every built-in Windows string off (see patch note)
    (void)AcpiUpdateInterfaces(ACPI_DISABLE_ALL_STRINGS);
    if (ACPI_FAILURE(s = AcpiInstallInterface((ACPI_STRING)"Darwin"))) IOLog("ACPI: _OSI Darwin: %s\n", AcpiFormatException(s));
    IOLog("ACPI: _OSI answers Darwin only\n");
    if (ACPI_FAILURE(s = AcpiInitializeTables(NULL, 32, TRUE)))      { IOLog("ACPI: table init: %s\n", AcpiFormatException(s)); return false; }
    if (ACPI_FAILURE(s = AcpiLoadTables()))                          { IOLog("ACPI: load tables: %s\n", AcpiFormatException(s)); return false; }
    if (ACPI_FAILURE(s = AcpiEnableSubsystem(ACPI_FULL_INITIALIZATION))) { IOLog("ACPI: enable: %s\n", AcpiFormatException(s)); return false; }
    if (ACPI_FAILURE(s = AcpiInitializeObjects(ACPI_FULL_INITIALIZATION))) { IOLog("ACPI: objects: %s\n", AcpiFormatException(s)); return false; }

    // Tell the firmware interrupts are routed through the I/O APIC (_PIC(1)); absent _PIC is normal.
    ACPI_OBJECT arg; arg.Type = ACPI_TYPE_INTEGER; arg.Integer.Value = 1;
    ACPI_OBJECT_LIST args = { 1, &arg };
    s = AcpiEvaluateObject(NULL, (ACPI_STRING)"\\_PIC", &args, NULL);
    if (ACPI_FAILURE(s) && s != AE_NOT_FOUND) IOLog("ACPI: _PIC(1): %s\n", AcpiFormatException(s));
    return true;
}

// Boot diagnostic (a2xbusydump=1): the root nub gets a private copy of its vtable whose adjustBusy slot logs the
// caller's backtrace (with kext names) and then calls the kernel's own. adjustBusy is virtual, so kext callers are
// invisible to a call-site scan. Slot +0x630 measured live (= IOService::adjustBusy + slide).
extern "C" void OSReportWithBacktrace(const char *str, ...);
static const size_t kA2XAdjustBusySlot = 0x630;
static void (*gA2XOrigAdjustBusy)(IOService *, SInt32);
static void A2XLoggedAdjustBusy(IOService *self, SInt32 delta)
{
    OSReportWithBacktrace("ACPI: root adjustBusy(%d) busy %u", (int)delta, self->getBusyState());
    gA2XOrigAdjustBusy(self, delta);
}
// Boot diagnostic (a2xbusydump=1): the vtable hook saw NO virtual adjustBusy on the root, so the leaked +1 comes
// from a direct kernel call of the non-virtual IOService::_adjustBusy(int,bool). Its 13-byte prologue (push rbp; mov
// rbp,rsp; push r15..rbx) is replaced by movabs rax,hook; jmp rax; the trampoline replays it and jumps back. Logged:
// every call on the root, and every 0<->1 transition of a service whose provider is the root (the propagation path).
// The target is decoded from the exported adjustBusy(int) wrapper (xor edx,edx; call rel32) and its prologue bytes are
// checked before anything is written; any mismatch logs and patches nothing.
extern "C" void _ZN9IOService10adjustBusyEi(void);
extern "C" uintptr_t gA2XAdjBusyCont;
uintptr_t gA2XAdjBusyCont;
extern "C" UInt32 A2XAdjBusyTramp(IOService *self, SInt32 delta, bool sync);
__asm__(".text\n.p2align 4\n_A2XAdjBusyTramp:\n"
        "  pushq %rbp\n  movq %rsp, %rbp\n  pushq %r15\n  pushq %r14\n  pushq %r13\n  pushq %r12\n  pushq %rbx\n"
        "  jmpq *_gA2XAdjBusyCont(%rip)\n");
static IOService *gA2XBusyRoot;
extern "C" UInt32 A2XAdjBusyHook(IOService *self, SInt32 delta, bool sync)
{
    // Exact: the root's count before and after this call. Any change is logged with the entry object, its provider
    // chain with each node's count (read after the call), and the caller's backtrace.
    IOService *root = gA2XBusyRoot;
    UInt32 rb0 = root ? root->getBusyState() : 0;
    UInt32 r = A2XAdjBusyTramp(self, delta, sync);
    if (root) {
        UInt32 rb1 = root->getBusyState();
        if (rb1 != rb0) {
            char chain[200]; size_t at = 0; chain[0] = 0;
            IOService *n = self;
            for (int depth = 0; n && n != root && depth < 12; depth++) {
                char one[64];
                snprintf(one, sizeof(one), "%s%s@%u", at ? "<" : "", n->getMetaClass()->getClassName(), n->getBusyState());
                size_t l = strlen(one);
                if (at + l + 1 >= sizeof(chain)) break;
                memcpy(chain + at, one, l + 1); at += l;
                n = n->getProvider();
            }
            OSReportWithBacktrace("ACPI: root %u -> %u by _adjustBusy(%d) on %s%s", rb0, rb1, (int)delta,
                                  self == root ? "root" : chain, (self != root && n != root) ? " (chain misses root)" : "");
        }
    }
    return r;
}
static void A2XPatchAdjustBusy(IOService *root)
{
    static const uint8_t pro[13] = { 0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53 };
    const uint8_t *w = (const uint8_t *)&_ZN9IOService10adjustBusyEi;
    uint8_t *t = NULL;
    for (int i = 0; i < 64 && !t; i++)
        if (w[i] == 0x31 && w[i + 1] == 0xd2 && (w[i + 2] == 0xe8 || w[i + 2] == 0xe9))
            t = (uint8_t *)(w + i + 7) + *(const int32_t *)(w + i + 3);
    if (!t || memcmp(t, pro, sizeof(pro))) { IOLog("ACPI: busy text hook: _adjustBusy not found (%p)\n", t); return; }
    gA2XAdjBusyCont = (uintptr_t)t + sizeof(pro);
    gA2XBusyRoot = root;
    uint8_t patch[13] = { 0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xe0, 0x90 };
    uintptr_t h = (uintptr_t)&A2XAdjBusyHook;
    memcpy(patch + 2, &h, 8);
    boolean_t ie = ml_set_interrupts_enabled(FALSE);
    uintptr_t cr0;
    __asm__ volatile("mov %%cr0, %0" : "=r"(cr0));
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0 & ~(uintptr_t)0x10000) : "memory");
    memcpy(t, patch, sizeof(patch));
    __asm__ volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");
    ml_set_interrupts_enabled(ie);
    IOLog("ACPI: busy text hook on _adjustBusy %p (root %p)\n", t, root);
}

static void A2XHookRootAdjustBusy(IOService *root)
{
    const size_t pre = 16, span = 0x1000;          // offset-to-top + typeinfo, then the slots
    uintptr_t *vt = *(uintptr_t **)root;
    uint8_t *copy = (uint8_t *)IOMalloc(pre + span);
    if (!copy) { IOLog("ACPI: rootbusy hook: no memory\n"); return; }
    memcpy(copy, (uint8_t *)vt - pre, pre + span);
    uintptr_t *nvt = (uintptr_t *)(copy + pre);
    gA2XOrigAdjustBusy = (void (*)(IOService *, SInt32))vt[kA2XAdjustBusySlot / 8];
    nvt[kA2XAdjustBusySlot / 8] = (uintptr_t)A2XLoggedAdjustBusy;
    *(uintptr_t **)root = nvt;
    IOLog("ACPI: rootbusy hook on %s: adjustBusy %p\n", root->getName(), (void *)gA2XOrigAdjustBusy);
}

// Boot diagnostic (a2xbusydump=1): log every change of the root nub's busy count for 120 s, so the serial lines
// around a transition name whoever raised it. The count must return to 0 once matching settles.
static void A2XRootBusyTrace(void *arg, wait_result_t)
{
    IOService *root = (IOService *)arg;
    UInt32 last = root->getBusyState();
    IOLog("ACPI: rootbusy t=0ms %u (trace start)\n", last);
    uint64_t t0 = mach_absolute_time(), now, ns;
    for (unsigned i = 0; i < 6000; i++) {
        IOSleep(20);
        UInt32 b = root->getBusyState();
        if (b != last) {
            now = mach_absolute_time(); absolutetime_to_nanoseconds(now - t0, &ns);
            IOLog("ACPI: rootbusy t=%llums %u -> %u\n", ns / 1000000, last, b);
            last = b;
            // Direct children's own counts: a root change no child accounts for is a direct adjustBusy on the root.
            OSIterator *ci = root->getClientIterator();
            if (ci) {
                OSObject *o;
                while ((o = ci->getNextObject())) {
                    IOService *c = OSDynamicCast(IOService, o);
                    if (c) IOLog("ACPI: rootbusy   child %s (%s) busy %u%s\n", c->getName(),
                                 c->getMetaClass()->getClassName(), c->getBusyState(), c->isInactive() ? " inactive" : "");
                }
                ci->release();
            }
        }
    }
    IOLog("ACPI: rootbusy trace end %u\n", last);
    root->release();
}

static const ACPI_TABLE_HEADER *gA2XDMAR;                      // see a2xVTdTranslationOff
static void a2xVTdTranslationOff(const ACPI_TABLE_HEADER *hdr);
bool A2XVTdStartMapper(const void *dmar, uint32_t len, IOService *platform);   // vtdmap.cpp
void A2XXHCIRouteStart(void);   // xhciroute.cpp

bool A2XACPIPlatformExpert::start(IOService *provider)
{
    {   // On-screen breadcrumbs (a counter and a ring of rows, top left) are a bring-up aid and are off by default:
        // a verbose start shows the kernel's own text, as on a Mac. Boot argument a2xcrumbs=1 draws them again.
        // Off, the crumbs still count (the heartbeat log reports them) but never map or draw the framebuffer.
        PE_Video v; bzero(&v, sizeof v);
        UInt32 crumbs = 0;
        if (PE_parse_boot_argn("a2xcrumbs", &crumbs, sizeof crumbs) && crumbs && getConsoleInfo(&v) == kIOReturnSuccess)
            a2x_crumb_init((uint64_t)v.v_baseAddr, (uint32_t)v.v_rowBytes, (uint32_t)v.v_width, (uint32_t)v.v_height, (uint32_t)v.v_depth);
    }
    {   // console-follow state (confollow.h) before any host bridge starts its configurator
        PE_Video v; bzero(&v, sizeof v);
        gCF.cur = (getConsoleInfo(&v) == kIOReturnSuccess) ? ((uint64_t)v.v_baseAddr & ~3ULL) : 0;
        UInt32 live = 0;
        gCF.live = PE_parse_boot_argn("a2x_conlive", &live, sizeof live) && live;
        gCFLock = IOLockAlloc();
        IOLog("ACPI: console follow on (boot screen 0x%llx)%s\n", (unsigned long long)gCF.cur,
              gCF.live ? ", a2x_conlive: disable requests DROPPED (diagnostic)" : "");
    }
    if (!initACPI()) return false;
    IOLog("ACPI: rootbusy at expert start %u\n", provider->getBusyState());
    if (UInt32 dump = 0; PE_parse_boot_argn("a2xbusydump", &dump, sizeof(dump)) && dump == 1) {   // full mode only: per-change root trace
        thread_t t;
        provider->retain();
        if (kernel_thread_start(A2XRootBusyTrace, provider, &t) == KERN_SUCCESS) thread_deallocate(t);
        else provider->release();
        A2XPatchAdjustBusy(provider);
    }
    fACPIReady = true;
    readMADT();
    publishTables();     // before IOPlatformExpert::start, which reads IOPlatformMapperPresent

    if (!IOACPIPlatformExpert::start(provider)) return false;
    if (gA2XDMAR) {   // mapper state is settled now; no device has started
        UInt32 on = 1;
        PE_parse_boot_argn("a2x_vtdmap", &on, sizeof on);
        if (!on || !A2XVTdStartMapper(gA2XDMAR, gA2XDMAR->Length, this)) a2xVTdTranslationOff(gA2XDMAR);
    }
    A2XXHCIRouteStart();   // before any PCI nub exists: Intel 7/8/9-series and X99 USB ports to xHCI

    // The platform interrupt controller comes first: the I/O APIC drivers and the PCI message controller
    // register under it, and the kernel delivers device vectors to it.
    fCPUInt = OSTypeAlloc(A2XCPUInterruptController);
    if (!fCPUInt || !fCPUInt->initController(this, fLapicID, fLapicCount)) {
        IOLog("ACPI: no CPU interrupt controller; device interrupts will not be delivered\n");
        fCPUInt = NULL;     // possibly already the kernel handler: never released
    }

    if (fCPUInt) { IOPCIPlatformInitialize(); fCPUInt->limitMessagesToBootCPU(); fCPUInt->startProcessors(); }
    // Boot diagnostic only: busy-service and timer dumps on the serial console, with boot-arg a2xbusydump=1.
    if (UInt32 dump = 0; PE_parse_boot_argn("a2xbusydump", &dump, sizeof(dump)) && dump) {
        gA2XBusyMode = dump;
        thread_t t;
        if (kernel_thread_start(A2XBusyDump, NULL, &t) == KERN_SUCCESS) thread_deallocate(t);
        if (kernel_thread_start(A2XIHMonitor, NULL, &t) == KERN_SUCCESS) thread_deallocate(t);
    }
    if (UInt32 dl = 0; PE_parse_boot_argn("a2x_deadline", &dl, sizeof(dl)) && dl >= 60) {
        gA2XDeadline = dl;
        thread_t t;
        if (kernel_thread_start(A2XDeadline, NULL, &t) == KERN_SUCCESS) thread_deallocate(t);
        IOLog("ACPI: a2x_deadline: restart in %u s\n", (unsigned)dl);
    }
    if (UInt32 rp = 0; PE_parse_boot_argn("a2xreadprobe", &rp, sizeof(rp)) && rp) {
        thread_t t;
        if (kernel_thread_start(A2XReadProbe, NULL, &t) == KERN_SUCCESS) thread_deallocate(t);
    }

    // The event controller exists before any nub, so nubs can carry event vectors from the start.
    fEvents = OSTypeAlloc(A2XACPIEventController);
    if (!fEvents || !fEvents->initController()) { OSSafeReleaseNULL(fEvents); IOLog("ACPI: no event controller\n"); }
    else {
        fEvents->attach(this);
        const OSSymbol *n = OSSymbol::withCString(kA2XEventControllerName);
        if (n) { registerInterruptController((OSSymbol *)n, fEvents); n->release(); }
    }

    publishNamespace(provider);
    publishFixedButtons();
    publishIOAPICs();

    // Firmware Notify() -> kIOACPIMessageDeviceNotification on the nub; clients read the code through the pointer.
    ACPI_STATUS s = AcpiInstallNotifyHandler(ACPI_ROOT_OBJECT, ACPI_ALL_NOTIFY, notifyHandler, this);
    if (ACPI_FAILURE(s)) IOLog("ACPI: notify handler: %s\n", AcpiFormatException(s));

    if (fCPUInt) fCPUInt->publishProcessors(fCPUNub, kA2XMaxCPUs);
    registerService();
    // The resource AppleACPIPlatformExpert published in the reference run; X86PlatformPlugin, VMPlatformPlugin and
    // ACPI_SMC_PlatformPlugin match on IOResourceMatch "ACPI". Published after the namespace and CPUs exist.
    publishResource("ACPI", this);
    if (fEvents && !startEvents()) IOLog("ACPI: SCI not started; ACPI events will not be delivered\n");
    IOLog("ACPI: rootbusy at expert start end %u\n", provider->getBusyState());
    return true;
}

IOReturn A2XACPIPlatformExpert::registerInterruptController(OSSymbol *name, IOInterruptController *ctl)
{
    IOReturn r = IOACPIPlatformExpert::registerInterruptController(name, ctl);
    IOLog("ACPI: interrupt controller \"%s\" (%s) registered: 0x%x\n", name ? name->getCStringNoCopy() : "?",
          ctl ? ctl->getMetaClass()->getClassName() : "?", r);
    if (r == kIOReturnSuccess && fCPUInt) fCPUInt->noteController(ctl);
    return r;
}

// IOPCIFamily asks the platform for its message controller and, per allocated source, for the message address
// and data a device writes. source = (cpu << 8) | vector, as the kernel delivers it; only CPU 0 runs.
extern "C" boolean_t ml_at_interrupt_context(void);

IOReturn A2XACPIPlatformExpert::callPlatformFunction(const OSSymbol *fn, bool wait, void *p1, void *p2,
                                                     void *p3, void *p4)
{
    const char *fnc = fn ? fn->getCStringNoCopy() : "???";
    A2XCrumbScope crumb(0x40, ((UInt32)(UInt8)fnc[0] << 16) | ((UInt32)(UInt8)(fnc[0] ? fnc[1] : 0) << 8) | (UInt8)((fnc[0] && fnc[1]) ? fnc[2] : 0));
    static UInt32 sAddrLogged;
    if (fn && fn->isEqualTo("GetMessagedInterruptController")) {
        IOInterruptController *msi = fCPUInt ? fCPUInt->messageController() : NULL;
        if (!msi || !p2) return kIOReturnUnsupported;        // IOPCIBridge then uses its own global
        *(IOInterruptController **)p2 = msi;
        return kIOReturnSuccess;
    }
    if (fn && fn->isEqualTo("GetMessagedInterruptAddress")) {
        struct MSIMessage { UInt64 address; UInt32 data; };
        UInt32 source = (UInt32)(uintptr_t)p3;
        if (!p4 || (source >> 8) != 0 || !fBSPFound) {
            if (!ml_at_interrupt_context()) IOLog("ACPI: no message address for source 0x%x\n", source);
            return kIOReturnBadArgument;
        }
        MSIMessage *m = (MSIMessage *)p4;
        m->address = 0xfee00000ULL | ((UInt64)(fBSPApicID & 0xff) << 12);   // fixed, physical destination
        m->data    = source & 0xff;                                        // edge, fixed delivery
        if (sAddrLogged < 16 && !ml_at_interrupt_context()) {
            sAddrLogged++;
            IOLog("ACPI: message source 0x%x for %s -> 0x%llx/0x%x\n", source,
                  p1 ? ((IOService *)p1)->getName() : "?", m->address, m->data);
        }
        return kIOReturnSuccess;
    }
    // PCI legacy interrupts (INTx): IOPCIBridge asks for the route of (device, pin) under its provider, then
    // hands the result back for the device's interrupt properties.
    // Apple answers these two for every device without ACPI power objects (SATA ports, for example): success, no-op
    if (fn && (fn->isEqualTo("IOPlatformDeviceMessage") || fn->isEqualTo("IOPlatformFreeDeviceResources")))
        return kIOReturnSuccess;
    if (fn && fn->isEqualTo("ResolvePCIInterrupt"))
        return resolvePCIInterrupt((IOService *)p1, (UInt32)(uintptr_t)p2, (UInt32)(uintptr_t)p3, (UInt32 *)p4);
    if (fn && fn->isEqualTo("SetDeviceInterrupts"))
        return setDeviceInterrupts((IOService *)p1, (const UInt32 *)p2, (UInt32)(uintptr_t)p3, p4 != NULL);
    if (wait && !ml_at_interrupt_context()) IOLog("ACPI: platform function %s called with wait\n", fn ? fn->getCStringNoCopy() : "?");
    IOReturn r = IOACPIPlatformExpert::callPlatformFunction(fn, wait, p1, p2, p3, p4);
    static volatile SInt32 sPFLogged;
    if (!ml_at_interrupt_context() && !fn->isEqualTo("IOPCIDeviceChanged") && OSIncrementAtomic(&sPFLogged) < 64)
        IOLog("ACPI: platform function %s wait %d -> 0x%x\n", fn ? fn->getCStringNoCopy() : "?", (int)wait, r);
    return r;
}

// ================================================================ MADT

void A2XACPIPlatformExpert::readMADT(void)
{
    ACPI_TABLE_HEADER *hdr = NULL;
    if (ACPI_FAILURE(AcpiGetTable((char *)ACPI_SIG_MADT, 1, &hdr)) || !hdr) { IOLog("ACPI: no MADT\n"); return; }
    UInt8 *p = (UInt8 *)hdr + sizeof(ACPI_TABLE_MADT);
    UInt8 *end = (UInt8 *)hdr + hdr->Length;
    while (p + sizeof(ACPI_SUBTABLE_HEADER) <= end) {
        ACPI_SUBTABLE_HEADER *sh = (ACPI_SUBTABLE_HEADER *)p;
        if (sh->Length < sizeof(ACPI_SUBTABLE_HEADER) || p + sh->Length > end) break;
        if (sh->Type == ACPI_MADT_TYPE_IO_APIC && fIOAPICCount < kA2XMaxIOAPIC) {
            ACPI_MADT_IO_APIC *io = (ACPI_MADT_IO_APIC *)p;
            fIOAPIC[fIOAPICCount].id = io->Id;
            fIOAPIC[fIOAPICCount].address = io->Address;
            fIOAPIC[fIOAPICCount].gsiBase = io->GlobalIrqBase;
            fIOAPICCount++;
        } else if (sh->Type == ACPI_MADT_TYPE_LOCAL_APIC) {
            // The first enabled local APIC is the boot processor (MADT ordering convention, ACPI 6.5 s5.2.12.2).
            ACPI_MADT_LOCAL_APIC *la = (ACPI_MADT_LOCAL_APIC *)p;
            if (la->LapicFlags & ACPI_MADT_ENABLED) {
                if (!fBSPFound) { fBSPApicID = la->Id; fBSPFound = true; }
                if (fLapicCount < kA2XMaxCPUs) fLapicID[fLapicCount++] = la->Id;
                if (fProcUIDCount < kA2XMaxCPUs) fProcUID[fProcUIDCount++] = la->ProcessorId;
            }
        } else if (sh->Type == ACPI_MADT_TYPE_LOCAL_X2APIC) {
            ACPI_MADT_LOCAL_X2APIC *xa = (ACPI_MADT_LOCAL_X2APIC *)p;
            if ((xa->LapicFlags & ACPI_MADT_ENABLED) && fLapicCount < kA2XMaxCPUs) fLapicID[fLapicCount++] = xa->LocalApicId;
            if ((xa->LapicFlags & ACPI_MADT_ENABLED) && fProcUIDCount < kA2XMaxCPUs) fProcUID[fProcUIDCount++] = xa->Uid;
        } else if (sh->Type == ACPI_MADT_TYPE_INTERRUPT_OVERRIDE) {
            ACPI_MADT_INTERRUPT_OVERRIDE *o = (ACPI_MADT_INTERRUPT_OVERRIDE *)p;
            if (o->SourceIrq < 16) {
                fISO[o->SourceIrq].present = 1;
                fISO[o->SourceIrq].gsi = o->GlobalIrq;
                fISO[o->SourceIrq].flags = o->IntiFlags;
            }
        }
        p += sh->Length;
    }
    AcpiPutTable(hdr);
}

// ISA IRQ -> GSI through the MADT overrides. Without an override an ISA IRQ is identity-mapped, edge, active high.
UInt32 A2XACPIPlatformExpert::gsiForIsaIrq(UInt32 irq, UInt32 *flags) const
{
    if (irq < 16 && fISO[irq].present) {
        UInt16 f = fISO[irq].flags;
        UInt32 out = 0;
        if ((f & ACPI_MADT_TRIGGER_MASK) == ACPI_MADT_TRIGGER_LEVEL) out |= kA2XIntLevel;
        if ((f & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_LOW) out |= kA2XIntActiveLow;
        *flags = out;
        return fISO[irq].gsi;
    }
    return irq;
}

UInt32 A2XACPIPlatformExpert::pinForGSI(UInt32 gsi) const
{
    UInt32 base = 0; bool found = false;
    for (UInt32 i = 0; i < fIOAPICCount; i++)
        if (fIOAPIC[i].gsiBase <= gsi && (!found || fIOAPIC[i].gsiBase >= base)) { base = fIOAPIC[i].gsiBase; found = true; }
    return gsi - base;
}

const OSSymbol *A2XACPIPlatformExpert::controllerForGSI(UInt32 gsi) const
{
    UInt32 best = 0; bool found = false;
    for (UInt32 i = 0; i < fIOAPICCount; i++) {
        if (fIOAPIC[i].gsiBase <= gsi && (!found || fIOAPIC[i].gsiBase >= fIOAPIC[best].gsiBase)) { best = i; found = true; }
    }
    char name[16];
    snprintf(name, sizeof name, "io-apic-%u", found ? best : 0);
    return OSSymbol::withCString(name);
}

// "ACPI Tables" = { signature: bytes }, repeated signatures as SSDT, SSDT-1, ... (the layout IOPCIFamily's VT-d
// driver reads DMAR from). IOPlatformMapperPresent is never set on 27: see the end of this function.
// Firmware on a real Mac leaves VT-d DMA translation switched on (Apple's pre-boot DMA protection) and expects its
// own remapping driver to take the units over. macOS 27.2 Intel ships no such driver, so every device's DMA then hits
// the firmware's tables: on the Mac Pro the NVMe disk never answered (no root device) and EHCI reported host system
// errors (0x20) for ever; Tahoe started with dart=0 lost its network the same way. So the translation the firmware
// left on is turned off here, unit by unit from the DMAR table, as Linux does for translation pre-enabled by firmware
// (Intel VT-d specification 11.4.4 and 11.4.5: GCMD at 0x18, GSTS at 0x1C, TE/TES bit 31). Interrupt remapping and
// the queued invalidation interface are left as they are: interrupts already arrive. Units the firmware left off
// are only reported.
// The DMAR table publishTables found (ACPICA keeps it mapped); the units are switched off after
// IOACPIPlatformExpert::start: mapping their registers any earlier waits for a system mapper for ever.
static void a2xVTdTranslationOff(const ACPI_TABLE_HEADER *hdr)
{
    const UInt8 *b = (const UInt8 *)hdr;
    UInt32 len = hdr->Length, off = 48;                    // ACPI header 36 + width 1 + flags 1 + reserved 10
    while (off + 4 <= len) {
        UInt16 type = (UInt16)(b[off] | (b[off + 1] << 8));
        UInt16 slen = (UInt16)(b[off + 2] | (b[off + 3] << 8));
        if (slen < 4 || off + slen > len) break;
        if (type == 0 && slen >= 16) {                     // DRHD: flags, size, segment, register base (u64 at +8)
            UInt64 base = 0;
            for (int i = 7; i >= 0; i--) base = (base << 8) | b[off + 8 + i];
            IOMemoryDescriptor *md = IOMemoryDescriptor::withPhysicalAddress(base, 0x1000, kIODirectionInOut);
            IOMemoryMap *map = md ? md->map(kIOMapInhibitCache) : NULL;
            if (map) {
                volatile UInt32 *r = (volatile UInt32 *)map->getVirtualAddress();
                UInt32 sts = r[0x1C / 4];
                if (sts & (1u << 31)) {
                    // the command is written from the persistent status bits (TE, QIE, IRE, CFI); one-shot bits not repeated
                    UInt32 cmd = sts & ((1u << 31) | (1u << 26) | (1u << 25) | (1u << 23));
                    r[0x18 / 4] = cmd & ~(1u << 31);
                    UInt32 t = 0;
                    while ((r[0x1C / 4] & (1u << 31)) && t < 1000) { IODelay(10); t++; }
                    UInt32 now = r[0x1C / 4];
                    IOLog("ACPI: VT-d unit 0x%llx: translation the firmware left on is %s (status 0x%08x -> 0x%08x)\n",
                          base, (now & (1u << 31)) ? "STILL ON" : "off", sts, now);
                } else {
                    IOLog("ACPI: VT-d unit 0x%llx: translation already off (status 0x%08x)\n", base, sts);
                }
                if (gA2XVTdCount < 8) { gA2XVTdRegs[gA2XVTdCount] = r; gA2XVTdBase[gA2XVTdCount++] = base; }   // kept mapped for the heartbeat
                else map->release();
            } else {
                IOLog("ACPI: VT-d unit 0x%llx: registers not mappable, left as they are\n", base);
            }
            if (md) md->release();
        }
        off += slen;
    }
}

void A2XACPIPlatformExpert::publishTables(void)
{
    OSDictionary *d = OSDictionary::withCapacity(16);
    if (!d) return;
    bool dmar = false;
    ACPI_TABLE_HEADER *hdr;
    for (UInt32 i = 0; ACPI_SUCCESS(AcpiGetTableByIndex(i, &hdr)); i++) {
        if (!hdr || hdr->Length < sizeof *hdr) continue;
        char key[16]; char sig[5];
        memcpy(sig, hdr->Signature, 4); sig[4] = 0;
        UInt32 n = 0;
        do { if (n) snprintf(key, sizeof key, "%s-%u", sig, n); else strlcpy(key, sig, sizeof key); n++; }
        while (d->getObject(key) && n < 64);
        UInt32 vtdmap = 1;
        PE_parse_boot_argn("a2x_vtdmap", &vtdmap, sizeof vtdmap);
        bool hideDMAR = vtdmap && !memcmp(sig, ACPI_SIG_DMAR, 4);   // see nodmarprop: AppleVTD would quiesce our mapper
        OSData *data = hideDMAR ? NULL : OSData::withBytes(hdr, hdr->Length);
        if (data) { d->setObject(key, data); data->release(); }
        if (!memcmp(sig, ACPI_SIG_DMAR, 4)) { dmar = true; gA2XDMAR = hdr; }
    }
    setProperty("ACPI Tables", d);
    d->release();
    // Not IOPlatformMapperPresent: on macOS 27.2 Intel nothing can answer it (the boot collection carries no VT-d
    // driver), and with it set IOPlatformExpert::start makes every DMA client wait in IOMapper::waitForSystemMapper
    // for ever. A Mac Pro (whose tables keep DMAR) stopped before its first disk that way; PCs only escaped it
    // because OpenCore's DisableIoMapper hid the table. Devices run without a remapper, as they do with dart=0.
    (void)dmar;
    IOLog("ACPI: tables published, DMA remapper %s\n", dmar ? "present" : "absent");
}

void A2XACPIPlatformExpert::publishIOAPICs(void)
{
    for (UInt32 i = 0; i < fIOAPICCount; i++) {
        OSDictionary *props = OSDictionary::withCapacity(8);
        if (!props) continue;
        char name[16];
        snprintf(name, sizeof name, "io-apic-%u", i);
        OSNumber *n;
        // Published sign-extended, as the platform always has (0xfec00000 -> 0xfffffffffec00000).
        if ((n = OSNumber::withNumber((UInt64)(SInt64)(SInt32)fIOAPIC[i].address, 64))) { props->setObject("Physical Address", n); n->release(); }
        if ((n = OSNumber::withNumber(fIOAPIC[i].id, 32)))      { props->setObject("APIC ID", n); n->release(); }
        if ((n = OSNumber::withNumber(fIOAPIC[i].gsiBase, 32))) { props->setObject("Interrupt Base", n); n->release(); }
        if ((n = OSNumber::withNumber(0x40 + fIOAPIC[i].gsiBase, 32))) { props->setObject("Base Vector Number", n); n->release(); }
        if ((n = OSNumber::withNumber(kA2XIOAPICVectorLimit, 32)))      { props->setObject("Vector Limit", n); n->release(); }
        if ((n = OSNumber::withNumber(fBSPApicID, 32)))                 { props->setObject("Destination APIC ID", n); n->release(); }
        OSString *cn = OSString::withCString(name);
        if (cn) { props->setObject("InterruptControllerName", cn); cn->release(); }
        // The I/O APIC's own parent: one interrupt on the platform controller, specifier 0.
        {
            const OSSymbol *pn = OSSymbol::withCString("IOPlatformInterruptController");
            UInt32 zero = 0;
            OSData *sp = OSData::withBytes(&zero, sizeof zero);
            OSArray *ca = pn ? OSArray::withObjects((const OSObject **)&pn, 1) : NULL;
            OSArray *sa = sp ? OSArray::withObjects((const OSObject **)&sp, 1) : NULL;
            if (ca && sa) { props->setObject("IOInterruptControllers", ca); props->setObject("IOInterruptSpecifiers", sa); }
            OSSafeReleaseNULL(ca); OSSafeReleaseNULL(sa); OSSafeReleaseNULL(sp); OSSafeReleaseNULL(pn);
        }

        IOACPIPlatformDevice *nub = OSTypeAlloc(IOACPIPlatformDevice);
        if (nub && nub->init(this, NULL, props)) {
            char loc[24];
            snprintf(loc, sizeof loc, "%x", fIOAPIC[i].address);
            nub->setName("io-apic");
            nub->setLocation(loc);
            // The register window, which the I/O APIC driver prefers over the Physical Address number.
            IODeviceMemory *m = IODeviceMemory::withRange(fIOAPIC[i].address, 0x1000);
            OSArray *ma = m ? OSArray::withObjects((const OSObject **)&m, 1) : NULL;
            if (ma) nub->setDeviceMemory(ma);
            OSSafeReleaseNULL(ma); OSSafeReleaseNULL(m);
            if (nub->attach(this)) nub->registerService();
        }
        OSSafeReleaseNULL(nub);
        props->release();
    }
}

// ================================================================ namespace -> nubs

// Device-tree nodes the base class must not turn into nubs (firmware data, not devices), and nodes to delete.
// 'packages' does not exist on these platforms; it keeps the delete list a valid, inert match list.
const char *A2XACPIPlatformExpert::deleteList(void)
{
    return "('packages')";
}

const char *A2XACPIPlatformExpert::excludeList(void)
{
    return "('chosen', 'memory', 'efi', 'rom', 'options', 'aliases')";
}

// See nondrv_patch: keep the firmware framebuffer driver off GPUs that a real driver will own.
static bool A2XNoNDRVPublished(void *, void *, IOService *svc, IONotifier *)
{
    IOPCIDevice *d = OSDynamicCast(IOPCIDevice, svc);
    if (!d) return true;
    UInt32 cls = d->configRead32(kIOPCIConfigRevisionID) >> 8;
    if ((cls >> 16) != 0x03) return true;                   // display controllers only
    d->setProperty("AAPL,iokit-ignore-ndrv", kOSBooleanTrue);
    IOLog("ACPI: %x:%x.%x class %06x: AAPL,iokit-ignore-ndrv (a2x_nondrv) - left for its real driver\n",
          d->getBusNumber(), d->getDeviceNumber(), d->getFunctionNumber(), cls);
    return true;
}

void A2XACPIPlatformExpert::publishNamespace(IOService *provider)
{
    if (UInt32 nondrv = 0; PE_parse_boot_argn("a2x_nondrv", &nondrv, sizeof nondrv) && nondrv) {
        IONotifier *n = IOService::addMatchingNotification(gIOFirstPublishNotification,
            IOService::serviceMatching("IOPCIDevice"), A2XNoNDRVPublished, NULL, NULL, 1000);
        IOLog("ACPI: a2x_nondrv: display functions are kept from IONDRVFramebuffer%s\n", n ? "" : " - NOTIFIER FAILED");
    }
    fDTRoot = provider;
    fDTCpus = provider->childFromPath("cpus", gIODTPlane);  // retained; created from the device tree by the base class
    provider->attachToParent(getRegistryRoot(), gIOACPIPlane);
    fDeferredNubs = OSArray::withCapacity(64);
    publishChildren(ACPI_ROOT_OBJECT, provider, NULL);
    // Every node (and its _DSM properties) now exists: matching can start, and PCI pairs each device with its node.
    OSArray *pending = fDeferredNubs; fDeferredNubs = NULL;
    if (pending) {
        for (unsigned i = 0; i < pending->getCount(); i++)
            if (IOService *n = OSDynamicCast(IOService, pending->getObject(i))) n->registerService();
        IOLog("ACPI: namespace published, %u nubs registered\n", pending->getCount());
        A2XStartDisplayKick(fCPUInt, fBSPApicID & 0xff);   // same id GetMessagedInterruptAddress uses
        pending->release();
    }
    OSSafeReleaseNULL(fDTCpus);
}

// Device-tree plane: \_SB's children sit at the device-tree root and their descendants nest under them, so
// IODeviceTree paths (PciRoot(0x0)/Pci(...) in boot-loader device properties) resolve to ACPI nubs.
// ACPI has two ways to declare a processor: the Processor() object, and since ACPI 5 a Device whose _HID is
// "ACPI0007" with the processor's number in _UID (ACPI 6.5 section 8.4; the first form is deprecated). Firmware for
// AMD processors of the last several years uses only the second, in a container device \_SB.PLTF: of twelve AMD
// machines' tables looked at, ten had no Processor() object at all. A machine like that got no processor nub here,
// so nothing that matches a processor (the processor driver's publication, the power-management plug-in, sensor
// drivers) ever started. AppleACPIPlatform treats both forms alike; so does this.
static bool A2XIsProcessorDevice(ACPI_HANDLE h)
{
    ACPI_DEVICE_INFO *info = NULL;
    if (ACPI_FAILURE(AcpiGetObjectInfo(h, &info)) || !info) return false;
    bool yes = info->Type == ACPI_TYPE_DEVICE && (info->Valid & ACPI_VALID_HID) && info->HardwareId.String
               && !strcmp(info->HardwareId.String, "ACPI0007");
    ACPI_FREE(info);
    return yes;
}

void A2XACPIPlatformExpert::publishChildren(ACPI_HANDLE parent, IORegistryEntry *acpiParent, IORegistryEntry *dtParent)
{
    ACPI_HANDLE child = NULL;
    ACPI_HANDLE sb = NULL;
    (void)AcpiGetHandle(NULL, (ACPI_STRING)"\\_SB_", &sb);
    while (ACPI_SUCCESS(AcpiGetNextObject(ACPI_TYPE_ANY, parent, child, &child))) {
        ACPI_OBJECT_TYPE type;
        if (ACPI_FAILURE(AcpiGetType(child, &type))) continue;
        if (type == ACPI_TYPE_DEVICE || type == ACPI_TYPE_PROCESSOR || type == ACPI_TYPE_POWER) {
            bool descend = true;
            bool isSB = (child == sb);
            bool isCPU = (type == ACPI_TYPE_PROCESSOR) || (type == ACPI_TYPE_DEVICE && A2XIsProcessorDevice(child));
            IORegistryEntry *dt = isCPU ? fDTCpus : (isSB ? NULL : dtParent);
            IOACPIPlatformDevice *nub = makeNub(child, type, acpiParent, dt, &descend);
            IORegistryEntry *childDT = isSB ? fDTRoot : (dt && nub ? (IORegistryEntry *)nub : NULL);
            if (descend) publishChildren(child, nub ? (IORegistryEntry *)nub : acpiParent, childDT);
            OSSafeReleaseNULL(nub);
        } else if (type == ACPI_TYPE_LOCAL_SCOPE) {
            publishChildren(child, acpiParent, dtParent);   // \_PR, \_GPE etc: walk through, no nub
        }
    }
}

static void A2XSetString(OSDictionary *d, const char *key, const char *s)
{
    OSString *o = OSString::withCString(s);
    if (o) { d->setObject(key, o); o->release(); }
}

static void A2XSetNumber(OSDictionary *d, const char *key, UInt64 v, UInt32 bits)
{
    OSNumber *o = OSNumber::withNumber(v, bits);
    if (o) { d->setObject(key, o); o->release(); }
}

// Apple's device-properties _DSM. Values as AppleACPIPlatform publishes them: integers as numbers, strings and
// buffers as data (strings keep their NUL). Returns how many properties were added.
static UInt32 A2XApplyAppleDSM(ACPI_HANDLE h, OSDictionary *props)
{
    ACPI_HANDLE m;
    if (ACPI_FAILURE(AcpiGetHandle(h, (ACPI_STRING)"_DSM", &m))) return 0;
    static UInt8 uuid[16] = { 0xc6, 0xb7, 0xb5, 0xa0, 0x18, 0x13, 0x1c, 0x44,      // a0b5b7c6-1318-441c-
                              0xb0, 0xc9, 0xfe, 0x69, 0x5e, 0xaf, 0x94, 0x9b };    // b0c9-fe695eaf949b
    ACPI_OBJECT args[4];
    args[0].Type = ACPI_TYPE_BUFFER;  args[0].Buffer.Length = 16; args[0].Buffer.Pointer = uuid;
    args[1].Type = ACPI_TYPE_INTEGER; args[1].Integer.Value = 1;   // revision
    args[2].Type = ACPI_TYPE_INTEGER; args[2].Integer.Value = 1;   // function 1: the properties
    args[3].Type = ACPI_TYPE_PACKAGE; args[3].Package.Count = 0; args[3].Package.Elements = NULL;
    ACPI_OBJECT_LIST list = { 4, args };
    ACPI_BUFFER out = { ACPI_ALLOCATE_BUFFER, NULL };
    if (ACPI_FAILURE(AcpiEvaluateObject(h, (ACPI_STRING)"_DSM", &list, &out)) || !out.Pointer) return 0;
    UInt32 n = 0;
    ACPI_OBJECT *r = (ACPI_OBJECT *)out.Pointer;
    if (r->Type == ACPI_TYPE_PACKAGE && r->Package.Count >= 2 && !(r->Package.Count & 1)) {
        for (UInt32 k = 0; k + 1 < r->Package.Count; k += 2) {
            ACPI_OBJECT *key = &r->Package.Elements[k], *val = &r->Package.Elements[k + 1];
            if (key->Type != ACPI_TYPE_STRING || !key->String.Pointer || !key->String.Length) continue;
            OSObject *o = NULL;
            if (val->Type == ACPI_TYPE_INTEGER)     o = OSNumber::withNumber((unsigned long long)val->Integer.Value, 32);
            else if (val->Type == ACPI_TYPE_STRING) o = OSData::withBytes(val->String.Pointer, val->String.Length + 1);
            else if (val->Type == ACPI_TYPE_BUFFER) o = OSData::withBytes(val->Buffer.Pointer, val->Buffer.Length);
            if (!o) continue;
            props->setObject(key->String.Pointer, o); o->release(); n++;
        }
    }
    ACPI_FREE(out.Pointer);
    return n;
}

static void A2XNubData(ACPI_HANDLE, void *)
{
    // Nothing to free: the data is a pointer to a registry entry owned by the registry.
}

IOACPIPlatformDevice *A2XACPIPlatformExpert::makeNub(ACPI_HANDLE h, ACPI_OBJECT_TYPE type, IORegistryEntry *acpiParent,
                                                     IORegistryEntry *dtParent, bool *descend)
{
    // _STA: a device neither present nor functioning is skipped with its whole subtree (ACPI 6.5 s6.3.7).
    UInt64 sta = ~0ULL;
    ACPI_BUFFER sb = { sizeof(ACPI_OBJECT), NULL };
    ACPI_OBJECT so;
    sb.Pointer = &so;
    if (ACPI_SUCCESS(AcpiEvaluateObjectTyped(h, (ACPI_STRING)"_STA", NULL, &sb, ACPI_TYPE_INTEGER))) {
        sta = so.Integer.Value;
        if (!(sta & (ACPI_STA_DEVICE_PRESENT | ACPI_STA_DEVICE_FUNCTIONING))) { *descend = false; return NULL; }
    }

    ACPI_DEVICE_INFO *info = NULL;
    if (ACPI_FAILURE(AcpiGetObjectInfo(h, &info)) || !info) return NULL;

    OSDictionary *props = OSDictionary::withCapacity(10);
    if (!props) { ACPI_FREE(info); return NULL; }

    char seg[5];
    memcpy(seg, &info->Name, 4); seg[4] = 0;
    bool registered = false;
    UInt32 cpuSlot = ~0u;

    if (info->Valid & ACPI_VALID_HID) {
        OSData *d = OSData::withBytes(info->HardwareId.String, info->HardwareId.Length);
        if (d) { props->setObject("name", d); d->release(); }
        registered = true;
    }
    if ((info->Valid & ACPI_VALID_CID) && info->CompatibleIdList.Count) {
        OSData *d = OSData::withCapacity(32);
        for (UInt32 i = 0; d && i < info->CompatibleIdList.Count; i++)
            d->appendBytes(info->CompatibleIdList.Ids[i].String, info->CompatibleIdList.Ids[i].Length);
        if (d) { props->setObject("compatible", d); d->release(); }
        registered = true;
    }
    if (info->Valid & ACPI_VALID_UID) A2XSetString(props, "_UID", info->UniqueId.String);
    if (info->Valid & ACPI_VALID_ADR) A2XSetNumber(props, "_ADR", info->Address, 64);
    A2XSetNumber(props, "_STA", sta, 64);

    char loc[24] = "";
    const bool cpuDevice = type == ACPI_TYPE_DEVICE && (info->Valid & ACPI_VALID_HID) && info->HardwareId.String
                           && !strcmp(info->HardwareId.String, "ACPI0007");
    if (cpuDevice) {
        // the processor's number is _UID, the value the interrupt table's local-APIC entries name it by; a _UID
        // that is not a number (the specification allows a string) leaves the number out rather than inventing one
        const char *u = (info->Valid & ACPI_VALID_UID) ? info->UniqueId.String : NULL;
        bool numeric = u && *u;
        for (const char *c = u; numeric && *c; c++) if (*c < '0' || *c > '9') numeric = false;
        if (numeric) {
            UInt32 id = (UInt32)strtoul(u, NULL, 10);
            A2XSetNumber(props, "processor-id", id, 32);
            snprintf(loc, sizeof loc, "%x", id);
        }
    }
    if (type == ACPI_TYPE_PROCESSOR || cpuDevice) {
        ACPI_BUFFER pb = { ACPI_ALLOCATE_BUFFER, NULL };
        if (type == ACPI_TYPE_PROCESSOR && ACPI_SUCCESS(AcpiEvaluateObject(h, NULL, NULL, &pb)) && pb.Pointer) {
            ACPI_OBJECT *po = (ACPI_OBJECT *)pb.Pointer;
            if (po->Type == ACPI_TYPE_PROCESSOR) {
                A2XSetNumber(props, "processor-id", po->Processor.ProcId, 32);
                snprintf(loc, sizeof loc, "%x", po->Processor.ProcId);
            }
            ACPI_FREE(pb.Pointer);
        }
        {   // device_type "processor": X86PlatformPlugin counts exactly these nubs and waits until each has published
            OSNumber *pid = OSDynamicCast(OSNumber, props->getObject("processor-id"));
            bool enabled = (fProcUIDCount == 0);
            for (UInt32 i = 0; pid && !enabled && i < fProcUIDCount; i++) enabled = (fProcUID[i] == pid->unsigned32BitValue());
            if (enabled) {
                OSData *dt = OSData::withBytes("processor", sizeof "processor");
                if (dt) { props->setObject("device_type", dt); dt->release(); }
            }
        }
        cpuSlot = fCPUIndex;
        A2XSetNumber(props, "processor-index", fCPUIndex++, 32);
        registered = true;
        {   // Apple tags CPU nubs compatible "processor"; SMCProcessor (and other CPU sensor drivers) IONameMatch it
            OSData *had = OSDynamicCast(OSData, props->getObject("compatible"));
            OSData *c = OSData::withCapacity(16);
            if (c) { if (had) c->appendBytes(had); c->appendBytes("processor", 10); props->setObject("compatible", c); c->release(); }
        }
    } else if (info->Valid & ACPI_VALID_ADR) {
        snprintf(loc, sizeof loc, "%llx", (unsigned long long)info->Address);
    }

    // PCI host bridges carry their _CRS windows and _PRT for the root-bridge driver.
    bool isRootBridge = (info->Flags & ACPI_PCI_ROOT_BRIDGE) != 0;
    if (isRootBridge) {
        ACPI_BUFFER rb = { ACPI_ALLOCATE_BUFFER, NULL };
        if (ACPI_SUCCESS(AcpiGetIrqRoutingTable(h, &rb)) && rb.Pointer) {
            // ACPICA's routing table is a run of ACPI_PCI_ROUTING_TABLE records ended by a zero Length.
            UInt8 *p = (UInt8 *)rb.Pointer, *e = p + rb.Length;
            while (p + sizeof(UInt32) <= e && ((ACPI_PCI_ROUTING_TABLE *)p)->Length) p += ((ACPI_PCI_ROUTING_TABLE *)p)->Length;
            OSData *d = OSData::withBytes(rb.Pointer, (unsigned)(p - (UInt8 *)rb.Pointer));
            if (d) { props->setObject("acpi-pci-routing-table", d); d->release(); }
            ACPI_FREE(rb.Pointer);
        }
        UInt32 cells = 3, scells = 2;
        OSData *d;
        if ((d = OSData::withBytes(&cells, 4)))  { props->setObject("#address-cells", d); d->release(); }
        if ((d = OSData::withBytes(&scells, 4))) { props->setObject("#size-cells", d); d->release(); }
    }

    // acpi-wake-type, as the platform publishes it: 2 = wakes through its _PRW GPE, 4 = the RTC fixed-event wake.
    ACPI_HANDLE prw;
    if (UInt32 dsm = A2XApplyAppleDSM(h, props)) IOLog("ACPI: %s: %u propert%s from _DSM\n", seg, dsm, dsm == 1 ? "y" : "ies");
    if (ACPI_SUCCESS(AcpiGetHandle(h, (ACPI_STRING)"_PRW", &prw))) A2XSetNumber(props, "acpi-wake-type", 2, 32);
    else if ((info->Valid & ACPI_VALID_HID) && !strcmp(info->HardwareId.String, "PNP0B00") && !AcpiGbl_ReducedHardware)
        A2XSetNumber(props, "acpi-wake-type", 4, 32);
    ACPI_FREE(info);

    IOACPIPlatformDevice *nub = OSTypeAlloc(IOACPIPlatformDevice);
    if (!nub || !nub->init(this, h, props)) { OSSafeReleaseNULL(nub); props->release(); return NULL; }
    props->release();
    nub->setName(seg);
    if (loc[0]) nub->setLocation(loc);
    if (type == ACPI_TYPE_PROCESSOR || cpuDevice) nub->setDeviceType(IOACPIPlatformDevice::kTypeProcessor);
    else if (type == ACPI_TYPE_POWER) nub->setDeviceType(IOACPIPlatformDevice::kTypePowerResource);

    // The namespace node points back at its nub, for Notify() delivery. Nubs live as long as the platform.
    (void)AcpiAttachData(h, A2XNubData, nub);

    if (cpuSlot < kA2XMaxCPUs) { nub->retain(); fCPUNub[cpuSlot] = nub; }
    nub->attachToParent(acpiParent, gIOACPIPlane);
    if (dtParent) nub->attachToParent(dtParent, gIODTPlane);
    // acpi-path, as Apple's platform sets it on every ACPI nub ("IOACPIPlane:/_SB/PCI0@0" on a real Mac). IOPCIFamily
    // reads it off the host bridge's provider to find the bridge's ACPI node, then pairs each PCI function with its
    // child by _ADR (IOPCIConfigurator IOPCICopyACPIDevice / matchACPIEntry). Without it no PCI device had an ACPI
    // node: VoodooI2C ("Could not get ACPI device for PCI provider"), backlight and _PSx power all went without.
    // The path is read back from the plane, so IORegistryEntry::fromPath always resolves it to this nub.
    {
        char path[512]; int len = (int)sizeof(path);
        if (!nub->getProperty("acpi-path") && nub->getPath(path, &len, gIOACPIPlane)) {
            OSString *ps = OSString::withCString(path);
            if (ps) { nub->setProperty("acpi-path", ps); ps->release(); }
        }
    }
    if (registered) {
        // Resources (and event vectors) are in place before any driver matches: IOService sizes a nub's
        // interrupt sources once, at its first interrupt call.
        (void)getNubResources(nub);
        OSData *hid = OSDynamicCast(OSData, nub->getProperty("name"));
        if (hid && hid->getLength() >= 7 && !memcmp(hid->getBytesNoCopy(), "PNP0B00", 7))
            IOLog("ACPI: RTC nub %s published\n", seg);
        if (nub->attach(this)) {
            if (fDeferredNubs) fDeferredNubs->setObject(nub);   // registered once every node exists
            else nub->registerService();
        }
    }
    return nub;
}

// ================================================================ name matching

// IONameMatch on an ACPI nub compares against the namespace segment (the IOName), then the _HID ("name") and every
// _CID ("compatible", NUL-separated). The base class compares the IOName only, so a driver matching "PNP0B00"
// (AppleRTC) would never see the RTC_ nub.
static bool A2XDataHasString(const OSData *d, const char *want, size_t wantLen)
{
    if (!d) return false;
    const char *p = (const char *)d->getBytesNoCopy();
    size_t n = d->getLength();
    while (p && n) {
        size_t len = strnlen(p, n);
        if (len == wantLen && !memcmp(p, want, len)) return true;
        if (len >= n) break;
        p += len + 1;
        n -= len + 1;
    }
    return false;
}

bool A2XACPIPlatformExpert::compareNubName(const IOService *nub, OSString *name, OSString **matched) const
{
    if (IOACPIPlatformExpert::compareNubName(nub, name, matched)) return true;
    if (!nub || !name) return false;
    const char *want = name->getCStringNoCopy();
    size_t wantLen = name->getLength();
    if (A2XDataHasString(OSDynamicCast(OSData, nub->getProperty("name")), want, wantLen) ||
        A2XDataHasString(OSDynamicCast(OSData, nub->getProperty("compatible")), want, wantLen)) {
        if (matched) { name->retain(); *matched = name; }
        static volatile SInt32 logged;
        if (OSIncrementAtomic(&logged) < 24) IOLog("ACPI: %s matched by id %s\n", nub->getName(), want);
        return true;
    }
    if (!strncmp(want, "PNP0B", 5)) IOLog("ACPI: %s did not match %s\n", nub->getName(), want);
    return false;
}

// ================================================================ resources (_CRS)

struct A2XCrs {
    A2XACPIPlatformExpert *pe;
    OSArray *mem, *specs, *ctrls, *spaces;
};

static void A2XAddRange(A2XCrs *c, UInt64 base, UInt64 len)
{
    if (!len) return;
    IODeviceMemory *m = IODeviceMemory::withRange((IOPhysicalAddress)base, (IOPhysicalLength)len);
    if (m) { c->mem->setObject(m); m->release(); }
}

static void A2XAddInterrupt(A2XCrs *c, UInt32 pin, UInt32 flags, const OSSymbol *ctrl)
{
    UInt32 spec[2] = { pin, flags };
    OSData *d = OSData::withBytes(spec, sizeof spec);
    if (d && ctrl) { c->specs->setObject(d); c->ctrls->setObject(ctrl); }
    OSSafeReleaseNULL(d);
}

// The bridge's ACPI node (the provider IOPCIBridge passes, or that provider's own provider) carries _PRT.
// An entry names either a GSI directly (empty Source) or a link device whose current resource is the GSI.
IOReturn A2XACPIPlatformExpert::resolvePCIInterrupt(IOService *bridge, UInt32 device, UInt32 pin, UInt32 *gsiOut)
{
    IOACPIPlatformDevice *dev = OSDynamicCast(IOACPIPlatformDevice, bridge);
    if (!dev && bridge) dev = OSDynamicCast(IOACPIPlatformDevice, bridge->getProvider());
    ACPI_HANDLE h = dev ? (ACPI_HANDLE)dev->getDeviceHandle() : NULL;
    if (!h || !gsiOut || pin > 3) return kIOReturnUnsupported;

    ACPI_BUFFER rb = { ACPI_ALLOCATE_BUFFER, NULL };
    if (ACPI_FAILURE(AcpiGetIrqRoutingTable(h, &rb)) || !rb.Pointer) return kIOReturnUnsupported;
    IOReturn r = kIOReturnNotFound;
    UInt32 gsi = 0, flags = kA2XIntLevel | kA2XIntActiveLow | kA2XIntShareable;   // PCI default
    UInt8 *p = (UInt8 *)rb.Pointer, *e = p + rb.Length;
    while (p + sizeof(UInt32) <= e) {
        ACPI_PCI_ROUTING_TABLE *t = (ACPI_PCI_ROUTING_TABLE *)p;
        if (!t->Length) break;
        if (((t->Address >> 16) & 0xffff) == device && t->Pin == pin) {
            if (!t->Source[0]) { gsi = t->SourceIndex; r = kIOReturnSuccess; break; }
            ACPI_HANDLE link = NULL;
            ACPI_BUFFER cb = { ACPI_ALLOCATE_BUFFER, NULL };
            if (ACPI_SUCCESS(AcpiGetHandle(h, t->Source, &link)) &&
                ACPI_SUCCESS(AcpiGetCurrentResources(link, &cb)) && cb.Pointer) {
                UInt8 *q = (UInt8 *)cb.Pointer, *qe = q + cb.Length;
                while (q + ACPI_RS_SIZE_NO_DATA <= qe && r != kIOReturnSuccess) {
                    ACPI_RESOURCE *res = (ACPI_RESOURCE *)q;
                    if (res->Type == ACPI_RESOURCE_TYPE_END_TAG || !res->Length) break;
                    if (res->Type == ACPI_RESOURCE_TYPE_EXTENDED_IRQ && res->Data.ExtendedIrq.InterruptCount) {
                        gsi = res->Data.ExtendedIrq.Interrupts[0];
                        flags = (res->Data.ExtendedIrq.Triggering == ACPI_LEVEL_SENSITIVE ? kA2XIntLevel : 0)
                              | (res->Data.ExtendedIrq.Polarity == ACPI_ACTIVE_LOW ? kA2XIntActiveLow : 0)
                              | (res->Data.ExtendedIrq.Shareable == ACPI_SHARED ? kA2XIntShareable : 0);
                        r = kIOReturnSuccess;
                    } else if (res->Type == ACPI_RESOURCE_TYPE_IRQ && res->Data.Irq.InterruptCount) {
                        UInt32 isoFlags = 0;
                        gsi = gsiForIsaIrq(res->Data.Irq.Interrupts[0], &isoFlags);
                        flags = (res->Data.Irq.Triggering == ACPI_LEVEL_SENSITIVE ? kA2XIntLevel : 0)
                              | (res->Data.Irq.Polarity == ACPI_ACTIVE_LOW ? kA2XIntActiveLow : 0)
                              | (res->Data.Irq.Shareable == ACPI_SHARED ? kA2XIntShareable : 0);
                        r = kIOReturnSuccess;
                    }
                    q += res->Length;
                }
            }
            if (cb.Pointer) ACPI_FREE(cb.Pointer);
            if (r != kIOReturnSuccess) IOLog("ACPI: PCI %u pin %c: link %s has no current interrupt\n",
                                              device, 'A' + pin, t->Source);
            break;
        }
        p += t->Length;
    }
    ACPI_FREE(rb.Pointer);
    if (r != kIOReturnSuccess || gsi > 0xff) return r == kIOReturnSuccess ? kIOReturnBadArgument : r;
    fPCIGSIFlags[gsi] = (UInt8)(flags | 0x80);
    *gsiOut = gsi;
    IOLog("ACPI: PCI %u pin %c -> GSI %u%s%s\n", device, 'A' + pin, gsi,
          (flags & kA2XIntLevel) ? " level" : " edge", (flags & kA2XIntActiveLow) ? " low" : " high");
    return kIOReturnSuccess;
}

// The vectors are GSIs from resolvePCIInterrupt; one IRQ line value IOPCIBridge read from config space when the
// route could not be resolved is an ISA IRQ, mapped through the interrupt source overrides.
IOReturn A2XACPIPlatformExpert::setDeviceInterrupts(IOService *nub, const UInt32 *vectors, UInt32 count, bool exclusive)
{
    if (!nub || !vectors || !count || count > 8) return kIOReturnBadArgument;
    {   // a bus-0 PCI-to-PCI bridge is a root port: no legacy line, its events stay with the downstream device
        OSData *cc = OSDynamicCast(OSData, nub->getProperty("class-code"));
        OSData *rg = OSDynamicCast(OSData, nub->getProperty("reg"));
        UInt32 cls = (cc && cc->getLength() >= 4) ? *(const UInt32 *)cc->getBytesNoCopy() : 0;
        UInt32 hi  = (rg && rg->getLength() >= 4) ? *(const UInt32 *)rg->getBytesNoCopy() : 0xffffffff;
        if ((cls >> 8) == 0x0604 && ((hi >> 16) & 0xff) == 0) {
            IOLog("ACPI: %s is a root port: no legacy interrupt\n", nub->getName());
            return kIOReturnSuccess;
        }
    }
    OSArray *specs = OSArray::withCapacity(count), *ctrls = OSArray::withCapacity(count);
    if (!specs || !ctrls) { OSSafeReleaseNULL(specs); OSSafeReleaseNULL(ctrls); return kIOReturnNoMemory; }
    for (UInt32 i = 0; i < count; i++) {
        UInt32 v = vectors[i], gsi, flags = 0;
        if (v <= 0xff && (fPCIGSIFlags[v] & 0x80)) { gsi = v; flags = fPCIGSIFlags[v] & 0x7f; }
        else { gsi = gsiForIsaIrq(v & 0xff, &flags); flags |= kA2XIntLevel; }
        if (!exclusive) flags |= kA2XIntShareable;
        UInt32 spec[2] = { pinForGSI(gsi), flags };
        OSData *d = OSData::withBytes(spec, sizeof spec);
        const OSSymbol *ctl = controllerForGSI(gsi);
        if (d && ctl) { specs->setObject(d); ctrls->setObject(ctl); }
        OSSafeReleaseNULL(d); OSSafeReleaseNULL(ctl);
        IOLog("ACPI: %s interrupt %u -> GSI %u flags 0x%x\n", nub->getName(), i, gsi, flags);
    }
    // IOPCIFamily appends message-signalled entries after these, so the legacy line stays index 0; any entries
    // already present are kept after it.
    OSArray *os = OSDynamicCast(OSArray, nub->getProperty(gIOInterruptSpecifiersKey));
    OSArray *oc = OSDynamicCast(OSArray, nub->getProperty(gIOInterruptControllersKey));
    if (os && oc && os->getCount() == oc->getCount()) { specs->merge(os); ctrls->merge(oc); }
    nub->setProperty(gIOInterruptSpecifiersKey, specs);
    nub->setProperty(gIOInterruptControllersKey, ctrls);
    specs->release(); ctrls->release();
    return kIOReturnSuccess;
}

IOReturn A2XACPIPlatformExpert::getNubResources(IOService *nub)
{
    IOACPIPlatformDevice *dev = OSDynamicCast(IOACPIPlatformDevice, nub);
    if (!dev) return IOACPIPlatformExpert::getNubResources(nub);
    // Built once: a second pass would drop event vectors appended by installDeviceInterruptFor*().
    if (nub->getDeviceMemory() || nub->getProperty(gIOInterruptSpecifiersKey) || nub->getProperty("acpi-address-spaces"))
        return kIOReturnSuccess;
    ACPI_HANDLE h = (ACPI_HANDLE)dev->getDeviceHandle();
    if (!h) return kIOReturnSuccess;    // synthetic nub (io-apic, power-button): nothing to evaluate

    A2XCrs c = { this, OSArray::withCapacity(4), OSArray::withCapacity(2), OSArray::withCapacity(2), OSArray::withCapacity(2) };
    if (!c.mem || !c.specs || !c.ctrls || !c.spaces) {
        OSSafeReleaseNULL(c.mem); OSSafeReleaseNULL(c.specs); OSSafeReleaseNULL(c.ctrls); OSSafeReleaseNULL(c.spaces);
        return kIOReturnNoMemory;
    }

    ACPI_BUFFER buf = { ACPI_ALLOCATE_BUFFER, NULL };
    if (ACPI_SUCCESS(AcpiGetCurrentResources(h, &buf)) && buf.Pointer) {
        UInt8 *p = (UInt8 *)buf.Pointer, *e = p + buf.Length;
        while (p + ACPI_RS_SIZE_NO_DATA <= e) {
            ACPI_RESOURCE *r = (ACPI_RESOURCE *)p;
            if (r->Type == ACPI_RESOURCE_TYPE_END_TAG || r->Length == 0) break;
            switch (r->Type) {
            case ACPI_RESOURCE_TYPE_IO:
                A2XAddRange(&c, r->Data.Io.Minimum, r->Data.Io.AddressLength); break;
            case ACPI_RESOURCE_TYPE_FIXED_IO:
                A2XAddRange(&c, r->Data.FixedIo.Address, r->Data.FixedIo.AddressLength); break;
            case ACPI_RESOURCE_TYPE_MEMORY24:
                A2XAddRange(&c, (UInt64)r->Data.Memory24.Minimum, r->Data.Memory24.AddressLength); break;
            case ACPI_RESOURCE_TYPE_MEMORY32:
                A2XAddRange(&c, r->Data.Memory32.Minimum, r->Data.Memory32.AddressLength); break;
            case ACPI_RESOURCE_TYPE_FIXED_MEMORY32:
                A2XAddRange(&c, r->Data.FixedMemory32.Address, r->Data.FixedMemory32.AddressLength); break;
            case ACPI_RESOURCE_TYPE_IRQ:
                for (UInt32 i = 0; i < r->Data.Irq.InterruptCount; i++) {
                    UInt32 flags = 0;
                    UInt32 gsi = gsiForIsaIrq(r->Data.Irq.Interrupts[i], &flags);
                    if (r->Data.Irq.Shareable == ACPI_SHARED) flags |= kA2XIntShareable;
                    const OSSymbol *ctl = controllerForGSI(gsi);
                    A2XAddInterrupt(&c, pinForGSI(gsi), flags, ctl);
                    OSSafeReleaseNULL(ctl);
                }
                break;
            case ACPI_RESOURCE_TYPE_EXTENDED_IRQ:
                if (r->Data.ExtendedIrq.ProducerConsumer != ACPI_CONSUMER) break;
                for (UInt32 i = 0; i < r->Data.ExtendedIrq.InterruptCount; i++) {
                    UInt32 flags = 0;
                    if (r->Data.ExtendedIrq.Triggering == ACPI_LEVEL_SENSITIVE) flags |= kA2XIntLevel;
                    if (r->Data.ExtendedIrq.Polarity == ACPI_ACTIVE_LOW) flags |= kA2XIntActiveLow;
                    if (r->Data.ExtendedIrq.Shareable == ACPI_SHARED) flags |= kA2XIntShareable;
                    const OSSymbol *ctl = controllerForGSI(r->Data.ExtendedIrq.Interrupts[i]);
                    A2XAddInterrupt(&c, pinForGSI(r->Data.ExtendedIrq.Interrupts[i]), flags, ctl);
                    OSSafeReleaseNULL(ctl);
                }
                break;
            case ACPI_RESOURCE_TYPE_ADDRESS16:
            case ACPI_RESOURCE_TYPE_ADDRESS32:
            case ACPI_RESOURCE_TYPE_ADDRESS64: {
                // Bridge windows: published as IOACPIAddressSpaceDescriptor records, not as device memory.
                ACPI_RESOURCE_ADDRESS64 a;
                if (ACPI_FAILURE(AcpiResourceToAddress64(r, &a))) break;
                if (a.ProducerConsumer != ACPI_PRODUCER && a.ResourceType != ACPI_BUS_NUMBER_RANGE) {
                    A2XAddRange(&c, a.Address.Minimum + a.Address.TranslationOffset, a.Address.AddressLength);
                    break;
                }
                IOACPIAddressSpaceDescriptor d;
                bzero(&d, sizeof d);
                d.resourceType      = a.ResourceType == ACPI_MEMORY_RANGE ? kIOACPIMemoryRange
                                    : a.ResourceType == ACPI_IO_RANGE ? kIOACPIIORange : kIOACPIBusNumberRange;
                d.granularity       = a.Address.Granularity;
                d.minAddressRange   = a.Address.Minimum;
                d.maxAddressRange   = a.Address.Maximum;
                d.translationOffset = a.Address.TranslationOffset;
                d.addressLength     = a.Address.AddressLength;
                OSData *od = OSData::withBytes(&d, sizeof d);
                if (od) { c.spaces->setObject(od); od->release(); }
                break;
            }
            default:
                break;
            }
            p += r->Length;
        }
        ACPI_FREE(buf.Pointer);
    }

    appendEventSpecs(dev, h, c.specs, c.ctrls);     // after _CRS, as published: RTC = (<8>, <ACPIEventController 4>)
    if (c.mem->getCount()) nub->setDeviceMemory(c.mem);
    if (c.specs->getCount()) {
        nub->setProperty(gIOInterruptSpecifiersKey, c.specs);
        nub->setProperty(gIOInterruptControllersKey, c.ctrls);
    }
    if (c.spaces->getCount()) {
        // One flat OSData of descriptors, as the root-bridge driver reads it.
        OSData *all = OSData::withCapacity(c.spaces->getCount() * sizeof(IOACPIAddressSpaceDescriptor));
        for (UInt32 i = 0; all && i < c.spaces->getCount(); i++) {
            OSData *od = OSDynamicCast(OSData, c.spaces->getObject(i));
            if (od) all->appendBytes(od);
        }
        if (all) { nub->setProperty("acpi-address-spaces", all); all->release(); }
    }
    c.mem->release(); c.specs->release(); c.ctrls->release(); c.spaces->release();
    return kIOReturnSuccess;
}

// ================================================================ evaluation

IOReturn A2XACPIPlatformExpert::status(ACPI_STATUS s)
{
    switch (s) {
    case AE_OK:            return kIOReturnSuccess;
    case AE_NOT_FOUND:     return kIOReturnNotFound;
    case AE_NO_MEMORY:     return kIOReturnNoMemory;
    case AE_TIME:          return kIOReturnTimeout;
    case AE_BAD_PARAMETER:
    case AE_TYPE:          return kIOReturnBadArgument;
    case AE_SUPPORT:       return kIOReturnUnsupported;
    case AE_ALREADY_EXISTS:return kIOReturnExclusiveAccess;
    default:               return kIOReturnError;
    }
}

OSObject *A2XACPIPlatformExpert::toOS(const ACPI_OBJECT *o, int depth)
{
    if (!o || depth > 8) return NULL;
    switch (o->Type) {
    case ACPI_TYPE_INTEGER:
        return OSNumber::withNumber(o->Integer.Value, 64);
    case ACPI_TYPE_STRING:
        return OSString::withCString(o->String.Pointer ? o->String.Pointer : "");
    case ACPI_TYPE_BUFFER:
        return OSData::withBytes(o->Buffer.Pointer, o->Buffer.Length);
    case ACPI_TYPE_PACKAGE: {
        OSArray *a = OSArray::withCapacity(o->Package.Count ? o->Package.Count : 1);
        for (UInt32 i = 0; a && i < o->Package.Count; i++) {
            OSObject *e = toOS(&o->Package.Elements[i], depth + 1);
            if (!e) e = OSData::withCapacity(0);    // keep element indices stable for unconvertible entries
            if (e) { a->setObject(e); e->release(); }
        }
        return a;
    }
    case ACPI_TYPE_LOCAL_REFERENCE: {
        char path[256];
        ACPI_BUFFER b = { sizeof path, path };
        if (o->Reference.Handle && ACPI_SUCCESS(AcpiGetName(o->Reference.Handle, ACPI_FULL_PATHNAME, &b)))
            return OSString::withCString(path);
        return NULL;
    }
    default:
        return NULL;
    }
}

bool A2XACPIPlatformExpert::fromOS(OSObject *in, ACPI_OBJECT *out, int depth)
{
    bzero(out, sizeof *out);
    if (depth > 4 || !in) return false;
    if (OSNumber *n = OSDynamicCast(OSNumber, in)) {
        out->Type = ACPI_TYPE_INTEGER; out->Integer.Value = n->unsigned64BitValue(); return true;
    }
    if (OSBoolean *b = OSDynamicCast(OSBoolean, in)) {
        out->Type = ACPI_TYPE_INTEGER; out->Integer.Value = b->isTrue() ? 1 : 0; return true;
    }
    if (OSString *s = OSDynamicCast(OSString, in)) {
        out->Type = ACPI_TYPE_STRING; out->String.Pointer = (char *)s->getCStringNoCopy(); out->String.Length = s->getLength();
        return true;
    }
    if (OSData *d = OSDynamicCast(OSData, in)) {
        out->Type = ACPI_TYPE_BUFFER; out->Buffer.Pointer = (UInt8 *)d->getBytesNoCopy(); out->Buffer.Length = d->getLength();
        return true;
    }
    if (OSArray *a = OSDynamicCast(OSArray, in)) {
        UInt32 n = a->getCount();
        ACPI_OBJECT *el = n ? (ACPI_OBJECT *)IOMallocZero(n * sizeof(ACPI_OBJECT)) : NULL;
        if (n && !el) return false;
        for (UInt32 i = 0; i < n; i++) {
            if (!fromOS(a->getObject(i), &el[i], depth + 1)) { freeParams(el, i, depth + 1); IOFree(el, n * sizeof(ACPI_OBJECT)); return false; }
        }
        out->Type = ACPI_TYPE_PACKAGE; out->Package.Count = n; out->Package.Elements = el;
        return true;
    }
    return false;
}

void A2XACPIPlatformExpert::freeParams(ACPI_OBJECT *objs, UInt32 count, int depth)
{
    for (UInt32 i = 0; objs && i < count; i++) {
        if (objs[i].Type == ACPI_TYPE_PACKAGE && objs[i].Package.Elements) {
            freeParams(objs[i].Package.Elements, objs[i].Package.Count, depth + 1);
            IOFree(objs[i].Package.Elements, objs[i].Package.Count * sizeof(ACPI_OBJECT));
        }
    }
}

IOReturn A2XACPIPlatformExpert::validateObject(IOACPIPlatformDevice *device, const OSSymbol *objectName)
{
    return objectName ? validateObject(device, objectName->getCStringNoCopy()) : kIOReturnBadArgument;
}

IOReturn A2XACPIPlatformExpert::validateObject(IOACPIPlatformDevice *device, const char *objectName)
{
    if (!device || !objectName) return kIOReturnBadArgument;
    ACPI_HANDLE out;
    return status(AcpiGetHandle((ACPI_HANDLE)device->getDeviceHandle(), (ACPI_STRING)objectName, &out));
}

IOReturn A2XACPIPlatformExpert::evaluateObject(IOACPIPlatformDevice *device, const OSSymbol *objectName, OSObject **result,
                                               OSObject *params[], IOItemCount paramCount, IOOptionBits options)
{
    return objectName ? evaluateObject(device, objectName->getCStringNoCopy(), result, params, paramCount, options)
                      : kIOReturnBadArgument;
}

IOReturn A2XACPIPlatformExpert::evaluateObject(IOACPIPlatformDevice *device, const char *objectName, OSObject **result,
                                               OSObject *params[], IOItemCount paramCount, IOOptionBits options)
{
    if (!device || !objectName || paramCount > ACPI_METHOD_NUM_ARGS) return kIOReturnBadArgument;
    if (result) *result = NULL;

    ACPI_OBJECT args[ACPI_METHOD_NUM_ARGS];
    for (IOItemCount i = 0; i < paramCount; i++) {
        if (!fromOS(params ? params[i] : NULL, &args[i], 0)) { freeParams(args, i, 0); return kIOReturnBadArgument; }
    }
    ACPI_OBJECT_LIST list = { paramCount, paramCount ? args : NULL };
    ACPI_BUFFER out = { ACPI_ALLOCATE_BUFFER, NULL };
    ACPI_STATUS s = AcpiEvaluateObject((ACPI_HANDLE)device->getDeviceHandle(), (ACPI_STRING)objectName,
                                       paramCount ? &list : NULL, result ? &out : NULL);
    freeParams(args, paramCount, 0);
    if (ACPI_SUCCESS(s) && result && out.Pointer) *result = toOS((ACPI_OBJECT *)out.Pointer, 0);
    if (out.Pointer) ACPI_FREE(out.Pointer);
    return status(s);
}

// ================================================================ tables

const OSData *A2XACPIPlatformExpert::getACPITableData(const char *tableName, UInt32 tableInstance)
{
    if (!tableName || strlen(tableName) != 4) return NULL;
    char key[24];
    snprintf(key, sizeof key, "%s-%u", tableName, tableInstance);

    IOLockLock(fLock);
    OSData *d = OSDynamicCast(OSData, fTables->getObject(key));
    if (!d) {
        ACPI_TABLE_HEADER *hdr = NULL;
        // ACPICA instances are 1-based; ours are 0-based.
        if (ACPI_SUCCESS(AcpiGetTable((char *)tableName, tableInstance + 1, &hdr)) && hdr) {
            d = OSData::withBytes(hdr, hdr->Length);
            AcpiPutTable(hdr);
            if (d) { fTables->setObject(key, d); d->release(); }
        }
    }
    IOLockUnlock(fLock);
    return d;   // owned by fTables for the life of the expert, as callers expect
}

// ================================================================ global lock

IOReturn A2XACPIPlatformExpert::acquireGlobalLock(IOService *client, UInt32 *lockToken, const mach_timespec_t *timeout)
{
    if (!lockToken) return kIOReturnBadArgument;
    UInt16 ms = ACPI_WAIT_FOREVER;
    if (timeout) {
        UInt64 t = (UInt64)timeout->tv_sec * 1000 + (UInt64)timeout->tv_nsec / 1000000;
        ms = t >= ACPI_WAIT_FOREVER ? ACPI_WAIT_FOREVER - 1 : (UInt16)t;
    }
    return status(AcpiAcquireGlobalLock(ms, lockToken));
}

void A2XACPIPlatformExpert::releaseGlobalLock(IOService *client, UInt32 lockToken)
{
    (void)AcpiReleaseGlobalLock(lockToken);
}

// ================================================================ address spaces

struct A2XSpaceHandler {
    ACPI_HANDLE               node;
    IOACPIAddressSpaceID      space;
    IOACPIAddressSpaceHandler handler;
    void                     *context;
};

static ACPI_STATUS A2XSpaceTrampoline(UINT32 Function, ACPI_PHYSICAL_ADDRESS Address, UINT32 BitWidth, UINT64 *Value,
                                      void *HandlerContext, void *RegionContext)
{
    A2XSpaceHandler *h = (A2XSpaceHandler *)HandlerContext;
    IOACPIAddress a; a.addr64 = Address;
    UInt32 op = (Function & ACPI_IO_MASK) == ACPI_READ ? kIOACPIAddressSpaceOpRead : kIOACPIAddressSpaceOpWrite;
    return h->handler(op, a, Value, BitWidth, 0, h->context) == kIOReturnSuccess ? AE_OK : AE_ERROR;
}

IOReturn A2XACPIPlatformExpert::registerAddressSpaceHandler(IOACPIPlatformDevice *device, IOACPIAddressSpaceID spaceID,
                                                            IOACPIAddressSpaceHandler handler, void *context, IOOptionBits)
{
    if (!device || !handler) return kIOReturnBadArgument;
    OSData *rec = OSData::withCapacity(sizeof(A2XSpaceHandler));
    if (!rec) return kIOReturnNoMemory;
    A2XSpaceHandler h = { (ACPI_HANDLE)device->getDeviceHandle(), spaceID, handler, context };
    rec->appendBytes(&h, sizeof h);
    A2XSpaceHandler *stored = (A2XSpaceHandler *)rec->getBytesNoCopy();

    ACPI_STATUS s = AcpiInstallAddressSpaceHandler(stored->node, (ACPI_ADR_SPACE_TYPE)spaceID, A2XSpaceTrampoline, NULL, stored);
    if (ACPI_SUCCESS(s)) {
        IOLockLock(fLock); fSpaceHandlers->setObject(rec); IOLockUnlock(fLock);
    }
    rec->release();
    return status(s);
}

void A2XACPIPlatformExpert::unregisterAddressSpaceHandler(IOACPIPlatformDevice *device, IOACPIAddressSpaceID spaceID,
                                                          IOACPIAddressSpaceHandler handler, IOOptionBits)
{
    if (!device) return;
    ACPI_HANDLE node = (ACPI_HANDLE)device->getDeviceHandle();
    IOLockLock(fLock);
    for (UInt32 i = 0; i < fSpaceHandlers->getCount(); i++) {
        OSData *rec = OSDynamicCast(OSData, fSpaceHandlers->getObject(i));
        A2XSpaceHandler *h = rec ? (A2XSpaceHandler *)rec->getBytesNoCopy() : NULL;
        if (h && h->node == node && h->space == spaceID && h->handler == handler) {
            IOLockUnlock(fLock);
            (void)AcpiRemoveAddressSpaceHandler(node, (ACPI_ADR_SPACE_TYPE)spaceID, A2XSpaceTrampoline);
            IOLockLock(fLock);
            fSpaceHandlers->removeObject(i);    // record freed only after ACPICA has stopped calling it
            break;
        }
    }
    IOLockUnlock(fLock);
}

static ACPI_STATUS A2XRawRead(IOACPIAddressSpaceID space, IOACPIAddress a, UInt32 width, UInt64 *v)
{
    switch (space) {
    case kIOACPIAddressSpaceIDSystemMemory:
        return AcpiOsReadMemory(a.addr64, v, width);
    case kIOACPIAddressSpaceIDSystemIO: {
        if (width > 32) return AE_BAD_PARAMETER;
        UINT32 x; ACPI_STATUS s = AcpiOsReadPort(a.addr64, &x, width); *v = x; return s;
    }
    case kIOACPIAddressSpaceIDPCIConfiguration: {
        ACPI_PCI_ID id = { (UINT16)a.pci.segment, (UINT16)a.pci.bus, (UINT16)a.pci.device, (UINT16)a.pci.function };
        return AcpiOsReadPciConfiguration(&id, a.pci.offset, v, width);
    }
    default:
        return AE_SUPPORT;
    }
}

static ACPI_STATUS A2XRawWrite(IOACPIAddressSpaceID space, IOACPIAddress a, UInt32 width, UInt64 v)
{
    switch (space) {
    case kIOACPIAddressSpaceIDSystemMemory:
        return AcpiOsWriteMemory(a.addr64, v, width);
    case kIOACPIAddressSpaceIDSystemIO:
        if (width > 32) return AE_BAD_PARAMETER;
        return AcpiOsWritePort(a.addr64, (UINT32)v, width);
    case kIOACPIAddressSpaceIDPCIConfiguration: {
        ACPI_PCI_ID id = { (UINT16)a.pci.segment, (UINT16)a.pci.bus, (UINT16)a.pci.device, (UINT16)a.pci.function };
        return AcpiOsWritePciConfiguration(&id, a.pci.offset, v, width);
    }
    default:
        return AE_SUPPORT;
    }
}

// A bit field is accessed through the smallest natural width that contains it.
static UInt32 A2XContainer(UInt32 bitWidth, UInt32 bitOffset)
{
    UInt32 need = bitWidth + bitOffset;
    return need <= 8 ? 8 : need <= 16 ? 16 : need <= 32 ? 32 : need <= 64 ? 64 : 0;
}

IOReturn A2XACPIPlatformExpert::readAddressSpace(UInt64 *value, IOACPIAddressSpaceID spaceID, IOACPIAddress address,
                                                 UInt32 bitWidth, UInt32 bitOffset, IOOptionBits)
{
    if (!value || !bitWidth) return kIOReturnBadArgument;
    UInt32 w = A2XContainer(bitWidth, bitOffset);
    if (!w) return kIOReturnBadArgument;
    UInt64 raw = 0;
    ACPI_STATUS s = A2XRawRead(spaceID, address, w, &raw);
    if (ACPI_FAILURE(s)) return status(s);
    UInt64 mask = bitWidth >= 64 ? ~0ULL : ((1ULL << bitWidth) - 1);
    *value = (raw >> bitOffset) & mask;
    return kIOReturnSuccess;
}

IOReturn A2XACPIPlatformExpert::writeAddressSpace(UInt64 value, IOACPIAddressSpaceID spaceID, IOACPIAddress address,
                                                  UInt32 bitWidth, UInt32 bitOffset, IOOptionBits)
{
    if (!bitWidth) return kIOReturnBadArgument;
    UInt32 w = A2XContainer(bitWidth, bitOffset);
    if (!w) return kIOReturnBadArgument;
    UInt64 out = value;
    if (bitOffset || bitWidth != w) {
        UInt64 raw = 0;
        ACPI_STATUS s = A2XRawRead(spaceID, address, w, &raw);     // read-modify-write keeps the neighbouring bits
        if (ACPI_FAILURE(s)) return status(s);
        UInt64 mask = (bitWidth >= 64 ? ~0ULL : ((1ULL << bitWidth) - 1)) << bitOffset;
        out = (raw & ~mask) | ((value << bitOffset) & mask);
    }
    return status(A2XRawWrite(spaceID, address, w, out));
}

// ================================================================ device power

// Preserve power dependencies through the provider chain. The generic platform
// implementation attaches every driver directly to the root domain, allowing a
// controller to power off while its ports still request usable power.
void A2XACPIPlatformExpert::PMRegisterDevice(IOService *nub, IOService *device)
{
    if (!device) return;
    IORegistryEntry *entry = nub;
    if (entry) entry->retain();
    for (unsigned depth = 0; entry && depth < 256; ++depth) {
        IORegistryEntry *next = entry->copyParentEntry(gIOServicePlane);
        IOService *parent = OSDynamicCast(IOService, entry);
        if (parent && parent != device && parent != this && parent->inPlane(gIOPowerPlane)) {
            IOReturn result = parent->addPowerChild(device);
            if (result != IOPMNotYetInitialized) {
                IOLog("ACPI: power parent %s -> %s result 0x%x\n", device->getName(), parent->getName(), result);
                entry->release();
                if (next) next->release();
                return;
            }
        }
        entry->release();
        entry = next;
    }
    if (entry) entry->release();
    IOACPIPlatformExpert::PMRegisterDevice(nub, device);
}


// True when this ACPI node names a PCI display-class device or a PCI device above one (see the patch note).
static bool A2XOnBootDisplayPath(IOService *acpiDev)
{
    const char *want = acpiDev->getName();
    if (!want) return false;
    OSDictionary *m = IOService::serviceMatching("IOPCIDevice");
    if (!m) return false;
    OSIterator *it = IOService::getMatchingServices(m);
    m->release();
    if (!it) return false;
    bool hit = false;
    while (!hit) {
        IOService *s = OSDynamicCast(IOService, it->getNextObject());
        if (!s) break;
        OSData *cc = OSDynamicCast(OSData, s->getProperty("class-code"));
        if (!cc || cc->getLength() < 3 || ((const UInt8 *)cc->getBytesNoCopy())[2] != 0x03) continue;
        for (IOService *q = s; q && !hit; q = q->getProvider())
            if (q->metaCast("IOPCIDevice") && q->getName() && !strcmp(q->getName(), want)) hit = true;
    }
    it->release();
    return hit;
}

IOReturn A2XACPIPlatformExpert::setDevicePowerState(IOACPIPlatformDevice *device, UInt32 powerState)
{
    if (!device || powerState >= kIOACPIDevicePowerStateCount) return kIOReturnBadArgument;
    if (powerState != 0) {
        if (A2XOnBootDisplayPath(device)) {
            IOLog("ACPI: _PS%u on %s refused: boot display path stays powered\n", (unsigned)powerState, device->getName());
            return kIOReturnSuccess;
        }
        IOLog("ACPI: _PS%u on %s\n", (unsigned)powerState, device->getName());   // before it runs, on purpose
    }
    char m[5] = { '_', 'P', 'S', (char)('0' + powerState), 0 };
    ACPI_STATUS s = AcpiEvaluateObject((ACPI_HANDLE)device->getDeviceHandle(), m, NULL, NULL);
    return s == AE_NOT_FOUND ? kIOReturnSuccess : status(s);    // no _PSx = nothing for firmware to do
}

IOReturn A2XACPIPlatformExpert::getDevicePowerState(IOACPIPlatformDevice *device, UInt32 *powerState)
{
    if (!device || !powerState) return kIOReturnBadArgument;
    ACPI_OBJECT o; ACPI_BUFFER b = { sizeof o, &o };
    ACPI_STATUS s = AcpiEvaluateObjectTyped((ACPI_HANDLE)device->getDeviceHandle(), (ACPI_STRING)"_PSC", NULL, &b, ACPI_TYPE_INTEGER);
    if (ACPI_FAILURE(s)) return status(s);
    *powerState = (UInt32)o.Integer.Value;
    return kIOReturnSuccess;
}

IOReturn A2XACPIPlatformExpert::setDeviceWakeEnable(IOACPIPlatformDevice *device, bool enable)
{
    if (!device) return kIOReturnBadArgument;
    ACPI_HANDLE h = (ACPI_HANDLE)device->getDeviceHandle();

    // _DSW(enable, target S-state 0, target D-state 0) per ACPI 6.5 s7.3.1; fall back to the older _PSW(enable).
    ACPI_OBJECT a[3];
    a[0].Type = ACPI_TYPE_INTEGER; a[0].Integer.Value = enable ? 1 : 0;
    a[1].Type = ACPI_TYPE_INTEGER; a[1].Integer.Value = 0;
    a[2].Type = ACPI_TYPE_INTEGER; a[2].Integer.Value = 0;
    ACPI_OBJECT_LIST l3 = { 3, a }, l1 = { 1, a };
    ACPI_STATUS s = AcpiEvaluateObject(h, (ACPI_STRING)"_DSW", &l3, NULL);
    if (s == AE_NOT_FOUND) s = AcpiEvaluateObject(h, (ACPI_STRING)"_PSW", &l1, NULL);
    if (ACPI_FAILURE(s) && s != AE_NOT_FOUND) return status(s);

    // Arm the wake GPE named by _PRW (simple integer form: GPE in the FADT GPE blocks).
    ACPI_BUFFER b = { ACPI_ALLOCATE_BUFFER, NULL };
    if (ACPI_SUCCESS(AcpiEvaluateObjectTyped(h, (ACPI_STRING)"_PRW", NULL, &b, ACPI_TYPE_PACKAGE)) && b.Pointer) {
        ACPI_OBJECT *p = (ACPI_OBJECT *)b.Pointer;
        if (p->Package.Count >= 2 && p->Package.Elements[0].Type == ACPI_TYPE_INTEGER) {
            UInt32 gpe = (UInt32)p->Package.Elements[0].Integer.Value;
            (void)AcpiSetupGpeForWake(h, NULL, gpe);
            (void)AcpiSetGpeWakeMask(NULL, gpe, enable ? ACPI_GPE_ENABLE : ACPI_GPE_DISABLE);
        }
        ACPI_FREE(b.Pointer);
    }
    return kIOReturnSuccess;
}

// ================================================================ events (vectors on the event controller)

// SCI routing: FADT SCI_INT through the MADT overrides. The SCI is level, active-low unless an override says
// otherwise (ACPI 6.5 s5.2.9); an override with "conforms" trigger/polarity keeps those defaults. Published = 5.
UInt32 A2XACPIPlatformExpert::sciGSI(UInt32 *flags) const
{
    UInt32 irq = AcpiGbl_FADT.SciInterrupt;
    UInt32 f = kA2XIntLevel | kA2XIntActiveLow;
    UInt32 gsi = irq;
    if (irq < 16 && fISO[irq].present) {
        UInt16 o = fISO[irq].flags;
        gsi = fISO[irq].gsi;
        if ((o & ACPI_MADT_TRIGGER_MASK) == ACPI_MADT_TRIGGER_EDGE) f &= ~(UInt32)kA2XIntLevel;
        if ((o & ACPI_MADT_POLARITY_MASK) == ACPI_MADT_POLARITY_ACTIVE_HIGH) f &= ~(UInt32)kA2XIntActiveLow;
    }
    *flags = f;
    return gsi;
}

bool A2XACPIPlatformExpert::startEvents(void)
{
    if (AcpiGbl_ReducedHardware) return true;   // hardware-reduced ACPI has no SCI; events come as GPIO interrupts
    UInt32 flags;
    UInt32 gsi = sciGSI(&flags);
    const OSSymbol *ctl = controllerForGSI(gsi);
    bool ok = fEvents->startSCI(pinForGSI(gsi), flags, ctl);
    OSSafeReleaseNULL(ctl);
    return ok;
}

// Event vectors a nub needs from the start (see makeNub): the RTC alarm fixed event on the RTC, and the GPE a
// device names in its own _GPE (embedded controller, LPSS devices).
void A2XACPIPlatformExpert::appendEventSpecs(IOACPIPlatformDevice *dev, ACPI_HANDLE h, OSArray *specs, OSArray *ctrls)
{
    if (!fEvents) return;
    const OSSymbol *ec = OSSymbol::withCString(kA2XEventControllerName);
    if (!ec) return;
    SInt64 v[2]; int n = 0;

    OSData *name = OSDynamicCast(OSData, dev->getProperty("name"));
    if (name && !AcpiGbl_ReducedHardware && name->getLength() >= 7 && !memcmp(name->getBytesNoCopy(), "PNP0B00", 7))
        v[n++] = fEvents->vectorForFixedEvent(ACPI_EVENT_RTC);

    ACPI_OBJECT o; ACPI_BUFFER b = { sizeof o, &o };
    if (ACPI_SUCCESS(AcpiEvaluateObjectTyped(h, (ACPI_STRING)"_GPE", NULL, &b, ACPI_TYPE_INTEGER)))
        v[n++] = fEvents->vectorForGPE(NULL, (UInt32)o.Integer.Value);

    for (int i = 0; i < n; i++) {
        if (v[i] < 0) continue;
        UInt32 spec[2] = { (UInt32)v[i], 0 };
        OSData *d = OSData::withBytes(spec, sizeof spec);
        if (d) { specs->setObject(d); ctrls->setObject(ec); d->release(); }
    }
    ec->release();
}

// Index of the event vector in the device's interrupt list; appended when not already there.
SInt32 A2XACPIPlatformExpert::addEventSpec(IOService *device, SInt64 vector)
{
    if (!device || vector < 0) return -1;
    if (OSDynamicCast(IOACPIPlatformDevice, device)) (void)getNubResources(device);

    SInt32 index = -1;
    IOLockLock(fLock);
    OSArray *specs = OSDynamicCast(OSArray, device->getProperty(gIOInterruptSpecifiersKey));
    OSArray *ctrls = OSDynamicCast(OSArray, device->getProperty(gIOInterruptControllersKey));
    UInt32 count = (specs && ctrls) ? (specs->getCount() < ctrls->getCount() ? specs->getCount() : ctrls->getCount()) : 0;
    for (UInt32 i = 0; i < count; i++) {
        OSData *d = OSDynamicCast(OSData, specs->getObject(i));
        OSString *c = OSDynamicCast(OSString, ctrls->getObject(i));
        if (d && c && d->getLength() >= 4 && c->isEqualTo(kA2XEventControllerName) &&
            *(const UInt32 *)d->getBytesNoCopy() == (UInt32)vector) { index = (SInt32)i; break; }
    }
    if (index < 0) {
        // A device that already resolved its interrupts will not see an entry added now (IOService sizes the
        // list once); the vectors drivers ask for are published up front by appendEventSpecs for that reason.
        OSArray *ns = specs ? OSArray::withArray(specs) : OSArray::withCapacity(1);
        OSArray *nc = ctrls ? OSArray::withArray(ctrls) : OSArray::withCapacity(1);
        UInt32 spec[2] = { (UInt32)vector, 0 };
        OSData *d = OSData::withBytes(spec, sizeof spec);
        const OSSymbol *ec = OSSymbol::withCString(kA2XEventControllerName);
        if (ns && nc && d && ec && ns->getCount() == nc->getCount()) {
            ns->setObject(d); nc->setObject(ec);
            device->setProperty(gIOInterruptSpecifiersKey, ns);
            device->setProperty(gIOInterruptControllersKey, nc);
            index = (SInt32)ns->getCount() - 1;
        }
        OSSafeReleaseNULL(ns); OSSafeReleaseNULL(nc); OSSafeReleaseNULL(d); OSSafeReleaseNULL(ec);
    }
    IOLockUnlock(fLock);
    return index;
}

SInt32 A2XACPIPlatformExpert::installDeviceInterruptForFixedEvent(IOService *device, UInt32 fixedEvent)
{
    if (!fEvents) return -1;
    return addEventSpec(device, fEvents->vectorForFixedEvent(fixedEvent));
}

// options: every caller in the OS passes 3; the GPE's own trigger type decides handling (see events.cpp).
SInt32 A2XACPIPlatformExpert::installDeviceInterruptForGPE(IOService *device, UInt32 gpeNumber, void *gpeBlockDevice,
                                                          IOOptionBits)
{
    if (!fEvents) return -1;
    return addEventSpec(device, fEvents->vectorForGPE((ACPI_HANDLE)gpeBlockDevice, gpeNumber));
}

// The fixed-hardware power button (FADT PWR_BUTTON clear) as its own nub, matched by the button driver.
void A2XACPIPlatformExpert::publishFixedButtons(void)
{
    if (!fEvents || AcpiGbl_ReducedHardware || (AcpiGbl_FADT.Flags & ACPI_FADT_POWER_BUTTON)) return;
    SInt64 v = fEvents->vectorForFixedEvent(ACPI_EVENT_POWER_BUTTON);
    OSDictionary *props = OSDictionary::withCapacity(4);
    UInt32 spec[2] = { (UInt32)v, 0 };
    OSData *d = OSData::withBytes(spec, sizeof spec);
    OSData *dt = OSData::withBytes("power-button", sizeof "power-button");
    const OSSymbol *ec = OSSymbol::withCString(kA2XEventControllerName);
    OSArray *specs = d ? OSArray::withObjects((const OSObject **)&d, 1) : NULL;
    OSArray *ctrls = ec ? OSArray::withObjects((const OSObject **)&ec, 1) : NULL;
    if (v >= 0 && props && dt && specs && ctrls) {
        props->setObject("device_type", dt);
        props->setObject(gIOInterruptSpecifiersKey, specs);
        props->setObject(gIOInterruptControllersKey, ctrls);
        A2XSetNumber(props, "acpi-wake-type", 1, 32);
        IOACPIPlatformDevice *nub = OSTypeAlloc(IOACPIPlatformDevice);
        if (nub && nub->init(this, NULL, props)) {
            nub->setName("power-button");
            if (nub->attach(this)) nub->registerService();
        }
        OSSafeReleaseNULL(nub);
    }
    OSSafeReleaseNULL(props); OSSafeReleaseNULL(d); OSSafeReleaseNULL(dt);
    OSSafeReleaseNULL(ec); OSSafeReleaseNULL(specs); OSSafeReleaseNULL(ctrls);
}

// Runs from ACPICA's notify queue (thread context).
void A2XACPIPlatformExpert::notifyHandler(ACPI_HANDLE h, UINT32 value, void *)
{
    void *p = NULL;
    if (ACPI_FAILURE(AcpiGetData(h, A2XNubData, &p)) || !p) return;
    IOService *nub = (IOService *)p;
    UInt32 code = value;
    nub->messageClients(kIOACPIMessageDeviceNotification, &code, sizeof code);
}

// ================================================================ halt / restart

// See confollow.h: nest the two configurators' disable/enable pairs and make the console follow a moved GPU BAR.
static_assert(kPEEnableScreen == CF_OP_ENABLE && kPEDisableScreen == CF_OP_DISABLE && kPEBaseAddressChange == CF_OP_BASE,
              "console op numbers (pexpert.h)");
IOReturn A2XACPIPlatformExpert::setConsoleInfo(PE_Video *consoleInfo, unsigned int op)
{
    if (op != kPEDisableScreen && op != kPEEnableScreen && op != kPEBaseAddressChange)
        return IOACPIPlatformExpert::setConsoleInfo(consoleInfo, op);
    if (gCFLock) IOLockLock(gCFLock);              // two configurator work loops can be here at once
    uint64_t nb = 0;
    int d0 = gCF.depth;
    unsigned a = cf_step(&gCF, op, (op == kPEBaseAddressChange && consoleInfo) ? (uint64_t)consoleInfo->v_baseAddr : 0,
                         a2x_console_where, NULL, &nb);
    IOReturn r = kIOReturnSuccess;
    if (a & CF_CRUMB_PAUSE) a2x_crumb_pause(1);
    if (a & CF_BASE_FIRST) {                       // the configurator moved the screen without telling the console
        PE_Video v; bzero(&v, sizeof v);
        getConsoleInfo(&v);                        // geometry as xnu has it; only the base changes
        v.v_baseAddr = (unsigned long)(nb | 1);    // bit 0: a physical address, initialize_screen maps it
        IOACPIPlatformExpert::setConsoleInfo(&v, kPEBaseAddressChange);
    }
    if (a & CF_FORWARD) r = IOACPIPlatformExpert::setConsoleInfo(consoleInfo, op);
    if (a & CF_CRUMB_MOVE) a2x_crumb_rebase(nb);
    if (a & CF_CRUMB_GO) a2x_crumb_pause(0);
    int d1 = gCF.depth;
    if (gCFLock) IOLockUnlock(gCFLock);
    IOLog("ACPI: console op %u depth %d->%d%s%s%s%s base 0x%llx\n", op, d0, d1,
          (a & CF_FORWARD) ? " forwarded" : " held", (a & CF_BASE_FIRST) ? " +OUR base change (configurator sent none)" : "",
          (a & CF_KEEP_OFF) ? " KEPT OFF (screen's device no longer decodes)" : "", gCF.live ? " [a2x_conlive]" : "",
          (unsigned long long)gCF.cur);
    return r;
}

// The IORTC (AppleRTC on the RTC_ PNP0B00 nub). Looked up by class like Apple's AppleACPIPlatformExpert, but the
// wait is BOUNDED (Apple's is infinite): 30 s, the same bound IOKitInitializeTime() already gave the IORTC resource,
// and only ONCE, only with interrupts enabled. Later calls (wake, settimeofday) never block. Cast by class NAME so
// the kext needs no com.apple.kpi.unsupported link for IORTC::metaClass.
static IORTC *volatile sA2XRTC;
static volatile SInt32 sA2XRTCWaited;
static IORTC *a2xFindRTC(void)
{
    IORTC *rtc = sA2XRTC;
    if (rtc) return rtc;
    OSDictionary *m = IOService::serviceMatching("IORTC");
    if (!m) return NULL;
    IOService *s = NULL;
    if (ml_get_interrupts_enabled() && OSCompareAndSwap(0, 1, &sA2XRTCWaited))
        s = IOService::waitForMatchingService(m, 30ULL * NSEC_PER_SEC);
    else
        s = IOService::copyMatchingService(m);
    m->release();
    if (s && !s->metaCast("IORTC")) { s->release(); s = NULL; }
    if (!s) {
        // Fail loud, once: the calendar stays where it is (epoch at boot) and the reason is in the log.
        static volatile SInt32 said;
        if (OSCompareAndSwap(0, 1, &said)) IOLog("A2X: no IORTC service - calendar not set from the RTC\n");
        return NULL;
    }
    // The cache keeps the retain from waitFor/copyMatchingService; AppleRTC is never unloaded.
    if (!OSCompareAndSwapPtr(NULL, s, (void * volatile *)&sA2XRTC)) s->release();
    return sA2XRTC;
}

void A2XACPIPlatformExpert::getUTCTimeOfDay(clock_sec_t *secs, clock_nsec_t *nsecs)
{
    IORTC *rtc = a2xFindRTC();
    if (!rtc) { IOACPIPlatformExpert::getUTCTimeOfDay(secs, nsecs); return; }
    rtc->getUTCTimeOfDay(secs, nsecs);
    static volatile SInt32 said;
    if (OSCompareAndSwap(0, 1, &said)) IOLog("A2X: calendar from IORTC: %lu s\n", (unsigned long)*secs);
}

void A2XACPIPlatformExpert::setUTCTimeOfDay(clock_sec_t secs, clock_nsec_t nsecs)
{
    IORTC *rtc = a2xFindRTC();
    if (rtc) rtc->setUTCTimeOfDay(secs, nsecs);
}

// ---------------------------------------------------------------- EFI device-properties (devprops.h)
// One parsed copy, built on the first IOPCIDevice registration.
// (the state variables sit right after OSDefineMetaClassAndStructors, so init() can allocate the lock)

static void a2xDPLoad(IOService *expert)
{
    const char *why = "no device-properties in IODeviceTree:/efi";
    IORegistryEntry *efi = IORegistryEntry::fromPath("/efi", gIODTPlane);
    OSData *d = efi ? OSDynamicCast(OSData, efi->getProperty("device-properties")) : NULL;
    if (d && d->getLength() >= 12 && d->getLength() <= A2X_DP_MAX_BLOB) {
        size_t len = d->getLength();
        uint8_t *copy = (uint8_t *)IOMalloc(len);
        a2x_dp_db *db = (a2x_dp_db *)IOMallocZero(sizeof(a2x_dp_db));
        if (copy && db) {
            bcopy(d->getBytesNoCopy(), copy, len);
            int r = a2x_dp_parse(copy, len, db, &why);
            if (r == 0) {
                a2xDPBlob = copy; a2xDPLen = len; a2xDP = db;
                IOLog("A2X DP: device-properties %lu bytes, %u device paths%s\n", (unsigned long)len, db->nnodes,
                      db->trailing ? " (trailing bytes ignored)" : "");
                for (UInt32 i = 0; i < db->nnodes; i++) {
                    char path[160]; a2x_dp_path_str(&db->node[i], path, sizeof path);
                    IOLog("A2X DP:   [%u] %s, %u properties\n", i, path, db->node[i].nprops);
                }
                __atomic_store_n(&a2xDPState, 1, __ATOMIC_RELEASE);
            } else {
                IOLog("A2X DP: device-properties REFUSED (%d: %s) - nothing applied\n", r, why);
                IOFree(copy, len); IOFree(db, sizeof(a2x_dp_db)); copy = NULL; db = NULL;
            }
        } else {
            why = "allocation failed";
            if (copy) IOFree(copy, len);
            if (db) IOFree(db, sizeof(a2x_dp_db));
        }
    } else if (d) why = "device-properties length out of bounds";
    if (efi) efi->release();
    if (__atomic_load_n(&a2xDPState, __ATOMIC_ACQUIRE) != 1) {
        __atomic_store_n(&a2xDPState, 2, __ATOMIC_RELEASE);
        if (d) IOLog("A2X DP: %s\n", why);
    }
    expert->setProperty("A2XDevicePropertiesState", why);
}

// The PCI path of an IOPCIDevice, root first, as an EFI device path names it: walk nub -> bridge driver -> parent
// nub ... until the provider is the ACPI host-bridge nub, whose _UID is the PciRoot UID. dev/fn come from "reg"
// (phys.hi bits 15:11 / 10:8), the same encoding IOPCIFamily wrote. Returns false when the chain is not that shape.
static bool a2xDPPathOf(IOService *nub, a2x_dp_node *out)
{
    a2x_dp_pci rev[A2X_DP_MAX_PCI]; UInt32 n = 0;
    IOService *cur = nub;
    for (;;) {
        if (n >= A2X_DP_MAX_PCI) return false;
        OSData *reg = OSDynamicCast(OSData, cur->getProperty("reg"));
        if (!reg || reg->getLength() < 4) return false;
        const uint8_t *b = (const uint8_t *)reg->getBytesNoCopy();
        UInt32 hi = (UInt32)b[0] | ((UInt32)b[1] << 8) | ((UInt32)b[2] << 16) | ((UInt32)b[3] << 24);
        rev[n].dev = (uint8_t)((hi >> 11) & 0x1f); rev[n].fn = (uint8_t)((hi >> 8) & 7); n++;
        IOService *bridge = cur->getProvider();
        IOService *up = bridge ? bridge->getProvider() : NULL;
        if (!up) return false;
        if (up->metaCast("IOPCIDevice")) { cur = up; continue; }
        if (!up->metaCast("IOACPIPlatformDevice")) return false;
        UInt64 uid = 0;
        OSObject *u = up->getProperty("_UID");
        if (OSNumber *num = OSDynamicCast(OSNumber, u)) { uid = num->unsigned64BitValue(); if (uid > 0xffffffffULL) return false; }
        else if (OSString *str = OSDynamicCast(OSString, u)) {
            uint32_t v = 0;
            if (!a2x_dp_parse_uid(str->getCStringNoCopy(), &v)) return false;   // "GigaLPCRS" never names a PciRoot
            uid = v;
        } else if (u) return false;                       // absent _UID = 0 (ACPI); anything else: no match
        out->supported = 1; out->uid = (uint32_t)uid; out->npci = n;
        for (UInt32 i = 0; i < n; i++) out->pci[i] = rev[n - 1 - i];
        return true;
    }
}

static void a2xDPApply(IOService *expert, IOService *nub)
{
    SInt32 st = __atomic_load_n(&a2xDPState, __ATOMIC_ACQUIRE);
    if (st == 0) {
        if (!a2xDPLock) return;
        IOLockLock(a2xDPLock);
        if (__atomic_load_n(&a2xDPState, __ATOMIC_ACQUIRE) == 0) a2xDPLoad(expert);
        IOLockUnlock(a2xDPLock);
        st = __atomic_load_n(&a2xDPState, __ATOMIC_ACQUIRE);
    }
    if (st != 1) return;
    a2x_dp_node me; bzero(&me, sizeof me);
    if (!a2xDPPathOf(nub, &me)) return;
    for (int i = a2x_dp_find(a2xDP, me.uid, me.pci, me.npci, 0); i >= 0;
         i = a2x_dp_find(a2xDP, me.uid, me.pci, me.npci, (uint32_t)i + 1)) {
        const a2x_dp_node *n = &a2xDP->node[i];
        char path[160]; a2x_dp_path_str(n, path, sizeof path);
        UInt32 idx = 0, cur = n->props_off, set = 0, skip = 0;
        a2x_dp_prop p;
        while (a2x_dp_next_prop(a2xDPBlob, a2xDPLen, n, &idx, &cur, &p)) {
            if (!p.key_ok || a2x_dp_key_denied(p.key)) {
                skip++;
                IOLog("A2X DP: %s: property %s refused\n", path, p.key_ok ? p.key : "<non-ASCII key>");
                continue;
            }
            OSData *v = OSData::withBytes(p.val, p.vlen);
            if (v) { nub->setProperty(p.key, v); v->release(); set++; } else skip++;
        }
        IOLockLock(a2xDPLock);
        a2xDPApplied += set; a2xDPSkipped += skip; a2xDPDevices++; a2xDPHit |= 1ULL << i;
        UInt32 unmatched = 0;
        for (UInt32 k = 0; k < a2xDP->nnodes; k++) unmatched += !(a2xDPHit & (1ULL << k));
        // Readable from userspace: ioreg -c A2XACPIPlatformExpert | grep A2XDeviceProperties
        expert->setProperty("A2XDevicePropertiesDevices", a2xDPDevices, 32);
        expert->setProperty("A2XDevicePropertiesSet", a2xDPApplied, 32);
        expert->setProperty("A2XDevicePropertiesRefused", a2xDPSkipped, 32);
        expert->setProperty("A2XDevicePropertiesUnmatchedPaths", unmatched, 32);
        IOLockUnlock(a2xDPLock);
        IOLog("A2X DP: %s -> %s: %u properties set, %u refused\n", path, nub->getName(), set, skip);
    }
}

bool A2XACPIPlatformExpert::platformAdjustService(IOService *service)
{
    if (service && service->metaCast("IOPCIDevice")) a2xDPApply(this, service);
    return IOACPIPlatformExpert::platformAdjustService(service);
}

struct A2XPalRegs { uint64_t rcx, rdx, r8, r9, rax; };
extern "C" {
kern_return_t pal_efi_call_in_64bit_mode(uint64_t func, struct A2XPalRegs *r, void *stack, size_t stack_size, uint64_t *status);
extern void *gPEEFIRuntimeServices;
}
// Panic context: no locks, no allocation, no IOLog. Static buffers only.
IOByteCount A2XACPIPlatformExpert::savePanicInfo(UInt8 *buffer, IOByteCount length)
{
    static const UInt8 guid[16] = { 0x10,0x61,0x43,0x7c, 0x2a,0xab, 0xbb,0x4b, 0xa8,0x80,0xfe,0x41,0x99,0x5c,0x9f,0x82 };
    static UInt16 name[16];
    static UInt8 chunk[1024];
    static UInt64 stack[8];
    UInt32 off = 0;
    if (!buffer || !length) return 0;
    UInt32 v = 1;
    if (PE_parse_boot_argn("a2x_panicsave", &v, sizeof v) && !v) return 0;
    const UInt8 *rt = (const UInt8 *)gPEEFIRuntimeServices;
    if (!rt) return 0;
    UInt64 sig; UInt32 hsize; UInt64 fn;
    memcpy(&sig, rt, 8); memcpy(&hsize, rt + 12, 4);
    if (sig != 0x56524553544e5552ULL || hsize < 96) return 0;      // "RUNTSERV", SetVariable at 88
    memcpy(&fn, rt + 88, 8);
    if (!fn) return 0;
    UInt32 total = length > 4 * 1000 - 8 ? 4 * 1000 - 8 : (UInt32)length;
    for (UInt32 k = 0; k < 4 && off < total; k++) {
        UInt32 n = 0;
        if (k == 0) { memcpy(chunk, "A2XP", 4); memcpy(chunk + 4, &total, 4); n = 8; }
        UInt32 take = total - off; if (take > 1000 - n) take = 1000 - n;
        memcpy(chunk + n, buffer + off, take); n += take; off += take;
        static const char base[] = "a2x-panic0";
        for (unsigned i = 0; i < sizeof base; i++) name[i] = (UInt16)(UInt8)base[i];
        name[9] = (UInt16)('0' + k);
        for (unsigned i = 0; i < 8; i++) stack[i] = 0;
        stack[4] = (UInt64)(uintptr_t)chunk;
        A2XPalRegs r = { (UInt64)(uintptr_t)name, (UInt64)(uintptr_t)guid, 7, n, 0 };
        UInt64 status = 1;
        if (pal_efi_call_in_64bit_mode(fn, &r, stack, 48, &status) != KERN_SUCCESS || status) return k ? off : 0;
    }
    return off;
}

int A2XACPIPlatformExpert::haltRestart(unsigned int type)
{
    switch (type) {
    case kPERestartCPU:
    case kPEPanicRestartCPU:
        if (fACPIReady) (void)AcpiReset();      // FADT reset register; no locks taken
        outb(0xcf9, 0x02); IODelay(50); outb(0xcf9, 0x06);  // PCI reset control: hard reset
        IODelay(100000);
        outb(0x64, 0xfe);                       // keyboard controller pulse, last resort
        for (;;) __asm__ volatile("hlt");
    case kPEHaltCPU:
    case kPEUPSDelayHaltCPU:
        if (fACPIReady) {
            if (ACPI_SUCCESS(AcpiEnterSleepStatePrep(ACPI_STATE_S5))) {
                ml_set_interrupts_enabled(FALSE);
                (void)AcpiEnterSleepState(ACPI_STATE_S5);
            }
        }
        for (;;) __asm__ volatile("cli; hlt");
    case kPEHangCPU:
        for (;;) __asm__ volatile("cli; hlt");
    default:
        // Panic begin/end/sync, paging off, diagnostics: nothing to do on this platform.
        // IOACPIPlatformExpert::haltRestart calls through a hook only Apple's ACPI platform
        // installs; on ours it is NULL and every panic re-faulted at RIP 0 before printing.
        return 0;
    }
}
