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
1. No null byte is added after `read_max`.
2. Thanks to 1., In `chk_pw`, you can leak a heap pointer byte-by-byte (since once a character is mismatched, the function quits immediately).
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
        
    * After calling `strtok` on `gbuff`, the Feng shui becomes:
        ```
        ........ 0x000410
        AAAAAAAA AAAAAAAA
        AAAAAAAA AAAAAAAA
        ...
        AAAAAAAA AAAAAAAA
        BBBBBBBB 0x000200
        ```

        This is because `strtok` changes delimeters (".,!?") to null bytes. (`ord('!')` is 0x21).
4. Now, you can then create overlap chunks using techniques like House of einherjar. You can then modify pointers on the heap and achieve arbitrary read & write.
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
1. Try to turn arbitrary read & write into arbitrary malloc & free. There are many other ways to achieve the goal.
	* For me, I choose to free the `tcache_perthread_struct`, malloc the chunk again, then modify `tcache_perthread_struct->counts` and `tcache_perthread_struct->entries`.
2. `open` or `openat` are both disallowed by seccomp.
    * Luckily, the seccomp filter does not check the current architecture.
	* The syscall number of `preadv` is 0x127 in x64. At the same time, the syscall number of `openat` is 0x127 in x86. You can try to execute `x86` shellcode using heaven's gate, invoke `openat`, and change back to `x64`. 

More details can be examined in the script.

