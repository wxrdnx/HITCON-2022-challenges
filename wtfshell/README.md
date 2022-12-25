# wtfshell

## wtfshell 1

> Tag: pwn
> Score: 400
> Solves: 4

## wtfshell 2

> Tag: pwn
> Score: 421
> Solves: 3

## Introduction

**Note**: **This challenge is open source, do not waste your time reverse-engineering the binary**.

An uncanny shell full of math and curse words. 

There are two flags in this challenge:
1. The first flag is hidden in the `flag1` file inside the virtual file system (a.k.a. memory) and cannot be read even by the virtual root. Your goal is to pwn the binary and achieve **arbitrary memory read**.
2. The second flag (`flag2`) is located outside of the virtual file system. This means that you must pwn the binary and achieve **arbitrary code execution (open/read/write actually, due to seccomp)** in order to get the flag.

Server (America):
```
nc 35.233.147.96 42531
```
Server (Asia): 
```
nc 35.194.252.171 42531
```

## Solution

### Flag1
1. No null byte is added at the end of the buffer in `read_max`.
2. Thanks to 1., In `chk_pw`, you can leak a heap pointer byte-by-byte (this is because once a character is mismatched, the function quits immediately).
3.  In the main function, `gbuff`'s size is 0x410. Try creating chunks with the following layout:
    ```
    ........ 0x000410
    AAAAAAAA AAAAAAAA
    AAAAAAAA AAAAAAAA
    ...
    AAAAAAAA AAAAAAAA
    00000000 0x000221
    ↑
    Notice the zeros here
    ```
    The unfortunate thing is that the size of gbuff is 0x400. There are zeros before `0x211`.
	To fill the zeros, you can make use of the `realloc` function in `cmd_rip` or `cmd_wtf`.
    Using `xfree` is not possible because it clears chunk data before calling `free`. However, `realloc` calls `free` internally when comparing a large or small chunk. In other words, calling `xrealloc` allows you to invoke `free` internally and preserve old chunk data at the same time.
    To sum up, you can allocate a 0x410 chunk filled with `B`, free it using `realloc`, and malloc it back again. This way, the heap turns into:
    ```
    ........ 0x000410
    AAAAAAAA AAAAAAAA
    AAAAAAAA AAAAAAAA
    ...
    AAAAAAAA AAAAAAAA
    BBBBBBBB 0x000221
    ```
4. After calling `strtok` on `gbuff`, the Feng shui becomes:
    ```
    ........ 0x000410
    AAAAAAAA AAAAAAAA
    AAAAAAAA AAAAAAAA
    ...
    AAAAAAAA AAAAAAAA
    BBBBBBBB 0x000200
    ```
    This is because `strtok` changes delimeters (".,!?") to null bytes. (`ord('!')` is 0x21).
5. Now, you can then create overlap chunks using techniques like House of einherjar. You can then modify pointers on the heap and achieve arbitrary read & write.
	* Q: how to turn the Bs before `0x200` into `prev_size` ?
        ```
        ........ 0x000410
        AAAAAAAA AAAAAAAA
        AAAAAAAA AAAAAAAA
        ...
        AAAAAAAA AAAAAAAA
        BBBBBBBB 0x000200
        ```

        A: The answer is `remove_slash`. `remove_slash` replaces `/` with `\0`. Therefore, if the heap layout is as follows:

        ```
        ........ 0x000410
        AAAAAAAA AAAAAAAA
        AAAAAAAA AAAAAAAA
        ...
        AAAAAAAA AAAAAAAA
        ///////@ 0x000200
        ```
        After calling `remove_slash`, the Feng shui becomes
        ```
        ........ 0x000410
        AAAAAAAA AAAAAAAA
        AAAAAAAA AAAAAAAA
        ...
        AAAAAAAA AAAAAAAA
        \0\0...@ 0x000200
        ```
        which is essentially
        ```
        ........ 0x000410
        AAAAAAAA AAAAAAAA
        AAAAAAAA AAAAAAAA
        ...
        AAAAAAAA AAAAAAAA
        0x000040 0x000200
        ```

### Flag2
1. Try to turn arbitrary read & write into arbitrary malloc & free.
	* For me, I choose to free the `tcache_perthread_struct`, malloc the chunk again, then modify `tcache_perthread_struct->counts` and `tcache_perthread_struct->entries`. This is a rather stable arbitrary malloc / free primitive.
    * Of course, there are many other ways to achieve arbitrary malloc / free. Feel free to use techniques you feel comfortable with.
2. Next, to need to bypass the seccomp filter. 

    ```bash
    $ seccomp-tools dump ./wtfshell
     line  CODE  JT   JF      K
    =================================
     0000: 0x20 0x00 0x00 0x00000000  A = sys_number
     0001: 0x15 0x00 0x04 0x00000000  if (A != read) goto 0006
     0002: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
     0003: 0x15 0x00 0x01 0x00000000  if (A != 0x0) goto 0005
     0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0005: 0x06 0x00 0x00 0x00000000  return KILL
     0006: 0x20 0x00 0x00 0x00000000  A = sys_number
     0007: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0009
     0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0009: 0x20 0x00 0x00 0x00000000  A = sys_number
     0010: 0x15 0x00 0x06 0x00000009  if (A != mmap) goto 0017
     0011: 0x20 0x00 0x00 0x00000020  A = prot # mmap(addr, len, prot, flags, fd, pgoff)
     0012: 0x15 0x03 0x00 0x00000007  if (A == 0x7) goto 0016
     0013: 0x20 0x00 0x00 0x00000030  A = fd # mmap(addr, len, prot, flags, fd, pgoff)
     0014: 0x15 0x00 0x01 0xffffffff  if (A != 0xffffffff) goto 0016
     0015: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0016: 0x06 0x00 0x00 0x00000000  return KILL
     0017: 0x20 0x00 0x00 0x00000000  A = sys_number
     0018: 0x15 0x00 0x01 0x0000000b  if (A != munmap) goto 0020
     0019: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0020: 0x20 0x00 0x00 0x00000000  A = sys_number
     0021: 0x15 0x00 0x01 0x0000000c  if (A != brk) goto 0023
     0022: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0023: 0x20 0x00 0x00 0x00000000  A = sys_number
     0024: 0x15 0x00 0x01 0x00000027  if (A != getpid) goto 0026
     0025: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0026: 0x20 0x00 0x00 0x00000000  A = sys_number
     0027: 0x15 0x00 0x01 0x00000066  if (A != getuid) goto 0029
     0028: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0029: 0x20 0x00 0x00 0x00000000  A = sys_number
     0030: 0x15 0x00 0x01 0x00000068  if (A != getgid) goto 0032
     0031: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0032: 0x20 0x00 0x00 0x00000000  A = sys_number
     0033: 0x15 0x00 0x04 0x00000014  if (A != writev) goto 0038
     0034: 0x20 0x00 0x00 0x00000010  A = fd # writev(fd, vec, vlen)
     0035: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0037
     0036: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0037: 0x06 0x00 0x00 0x00000000  return KILL
     0038: 0x20 0x00 0x00 0x00000000  A = sys_number
     0039: 0x15 0x00 0x05 0x0000003c  if (A != exit) goto 0045
     0040: 0x20 0x00 0x00 0x00000010  A = error_code # exit(error_code)
     0041: 0x15 0x01 0x00 0x00000000  if (A == 0x0) goto 0043
     0042: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0044
     0043: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0044: 0x06 0x00 0x00 0x00000000  return KILL
     0045: 0x20 0x00 0x00 0x00000000  A = sys_number
     0046: 0x15 0x00 0x05 0x000000e7  if (A != exit_group) goto 0052
     0047: 0x20 0x00 0x00 0x00000010  A = error_code # exit_group(error_code)
     0048: 0x15 0x01 0x00 0x00000000  if (A == 0x0) goto 0050
     0049: 0x15 0x00 0x01 0x00000001  if (A != 0x1) goto 0051
     0050: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0051: 0x06 0x00 0x00 0x00000000  return KILL
     0052: 0x20 0x00 0x00 0x00000000  A = sys_number
     0053: 0x15 0x00 0x03 0x00000127  if (A != preadv) goto 0057
     0054: 0x20 0x00 0x00 0x00000010  A = fd # preadv(fd, vec, vlen, pos_l, pos_h)
     0055: 0x25 0x00 0x01 0x00000002  if (A <= 0x2) goto 0057
     0056: 0x06 0x00 0x00 0x7fff0000  return ALLOW
     0057: 0x06 0x00 0x00 0x00000000  return KILL
     ```

    * Q: `open` or `openat` are both disallowed by seccomp. How to invoke `open` or `openat`?
    * A: Luckily, the seccomp filter does not check the current architecture. At the same time, the syscall number of `preadv` is 0x127 in x64, and coincidentally the syscall number of `openat` is 0x127 in x86. Therefore, you can switch to `x86` mode using the heaven's gate technique, invoke `openat`, switch back to `x64`, and invoke `read` & `writev`.

More details can be examined in the script.
