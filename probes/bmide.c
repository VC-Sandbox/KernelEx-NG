/* bmide.c - VM harness probe: the PIIX IDE bus-master registers as Windows 98 sees them (ring-3 port I/O works on 9x).
 * "bmide" prints them; "bmide set" also sets the "drive 0/1 DMA capable" bits (5, 6) of both channels' status. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned long pci_rd(int bus, int dev, int fn, int reg)
{
    unsigned long v, a = 0x80000000UL | (bus << 16) | (dev << 11) | (fn << 8) | (reg & 0xFC);
    __asm__ volatile("outl %0, %w1" :: "a"(a), "Nd"(0xCF8));
    __asm__ volatile("inl %w1, %0" : "=a"(v) : "Nd"(0xCFC));
    return v;
}
static unsigned char inb(unsigned short p) { unsigned char v; __asm__ volatile("inb %w1, %0" : "=a"(v) : "Nd"(p)); return v; }
static void outb(unsigned short p, unsigned char v) { __asm__ volatile("outb %0, %w1" :: "a"(v), "Nd"(p)); }
int main(int argc, char **argv)
{
    int dev; FILE *f = fopen("C:\\BMIDE.TXT", "w");
    for (dev = 0; dev < 32; dev++) {
        unsigned long id = pci_rd(0, dev, 1, 0), cls = pci_rd(0, dev, 1, 8), bar4, cmd, tim;
        unsigned short base; int ch;
        if ((id & 0xFFFF) != 0x8086 || ((cls >> 16) & 0xFFFF) != 0x0101) continue;
        bar4 = pci_rd(0, dev, 1, 0x20); cmd = pci_rd(0, dev, 1, 4); tim = pci_rd(0, dev, 1, 0x40);
        base = (unsigned short)(bar4 & 0xFFF0);
        fprintf(f, "IDE 00:%02x.1 id %08lx class %08lx cmd %08lx BAR4 %08lx IDETIM %08lx\n", dev, id, cls, cmd, bar4, tim);
        for (ch = 0; ch < 2; ch++) {
            unsigned short p = base + ch * 8;
            unsigned char st = inb(p + 2);
            fprintf(f, "  channel %d: BM command %02x status %02x (drive0 DMA-capable %d, drive1 %d, simplex %d)\n",
                    ch, inb(p), st, (st >> 5) & 1, (st >> 6) & 1, (st >> 7) & 1);
            if (argc > 1 && !strcmp(argv[1], "set")) {
                outb(p + 2, (unsigned char)((st & 0x60) | 0x60));   /* keep bits 5/6 set; writing 0 to bits 1/2 leaves them */
                fprintf(f, "  channel %d: status now %02x\n", ch, inb(p + 2));
            }
        }
    }
    fclose(f);
    return 0;
}
