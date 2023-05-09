# gocrygo

> Tag: Reverse
> Score: 248
> Solves: 33

## Solution

### Initial analysis

First, you can find an interesting string `clang version 14.0.0 (https://github.com/tinygo-org/llvm-project 1f20f113b6e577ff74484e925818378ffdb7a5d9)` in the binary, indicating that `gocrygo` was compiled with `tinygo`. Thus, you can conclude that the malware is written in Go. Unfortunately, unlike other "standard" go binaries, you cannot recover function names (It's stripped, it's compiled on LLVM, and it does not contain the `pclntab` section).

Second, you need to identify the main function. You can do this by cross-referencing promising strings.
In the binary, you might notice some base64 encoded strings like `PWA4RjFFYi1BKERmOUsoQTFldXBEZjkvL0NpczYnK0ZY`. Base64 decode it yields "=`8F1Eb-A(Df9K(A1eupDf9//Cis6'+FX". Then, base85 decode this string yields `You're doomed. Good luck ~`. After cross-referencing this string, you'll eventually land on `0x221A61`. Predictably, `0x221A61` is the main function.

### Encryption algorithm

Next, you need to figure out the encryption algorithm. There are many ways to do this
    1. Identify the `crypto/des` string in `gocrygo` (The malware may have used DES)
    2. Look for magic cryptographic numbers. For DES, you can search the IP (initial permutation) table.
        ```python
        >>> elf = open('gocrygo', 'rb')
        >>> elf_data = elf.read()
        >>> hex(elf_data.index(bytes([7, 15, 23, 31, 39, 47, 55, 63])))
        '0x233d6'
        >>> 
        ```
        As you can see, `0x233d6` contains the IP table.
    3. Notice the `cipher1`, `cipher2`, and `cipher3` strings. If you look for these strings in `/usr/local/go/src`, you might detect that these strings appear in `tripleDESCipher struct` and `func NewTripleDESCipher`, suggesing that the encryption scheme might me 3DES (TDEA) instead!

![](https://i.imgur.com/wIqZLX0.png)

![](https://i.imgur.com/7qfFOUr.png)

Moving on. Let's find the DES encryption functions. Knowing that `0x233d6` is the IP table, you'll ultimately stop at `sub_2126AE` after cross-referencing the string.

![](https://i.imgur.com/jQPM8EJ.png)

Unsurprisingly, `sub_2126AE` looks extremely similar to the subkey generation operation of DES.

If you continue on and cross-reference `sub_2126AE`, you'll land on function `sub_222A30` (You might need to adjust the function in IDA). Interestingly, `sub_222A30` calls `sub_2126AE` (subkey generation) thrice, verifying that the encryption algorithm is indeed 3DES.

![](https://i.imgur.com/AVSd8Km.png)

### Find the key

Moving on. You now know that the cryptographic scheme is 3DES. But, how do you excavate the key from the core dump? Again, there are several ways to do this. For example, encryption keys are usually generated using `/dev/urandom` on Linux. Hence, you can cross-reference the `/dev/urandom` string. If all goes well, you will eventually land on `sub_21FCCB`.

Attach the debugger and add a breakpoint at `0x222290`. Before executing `sub_21FCCB`, the rsi variable contains:

```
pwndbg> x/4xg 0x7fffb800d1a0
0x7fffb800d1a0:	0x0000000000000000	0x0000000000000000
0x7fffb800d1b0:	0x0000000000000000	0x0000000000000000
pwndbg>
```

After the execution, the `rsi` variable becomes

```
pwndbg> x/4xg 0x7fffb800d1a0
0x7fffb800d1a0:	0xaef2dbba98404626	0x3ec02e3b0d2cf7c4
0x7fffb800d1b0:	0xc965b0d4927ef351	0x0000000000000000
pwndbg>
```

Without a doubt, `sub_21FCCB` is the pseudo random number generator, and `0x7fffb800d1a0` contains the 24 byte (3 * 8 DES key) encryption key.

Sadly, The offset of `0x7fffb800d1a0` is not fixed. It changes everytime you execute the binary.
But luckily, the string at `0x7fffb800d1a0 + 0x20` is coincidentally `/dev/urandom`:

```
pwndbg> x/8xg 0x7fffb800d1a0
0x7fffb800d1a0:	0xaef2dbba98404626	0x3ec02e3b0d2cf7c4
0x7fffb800d1b0:	0xc965b0d4927ef351	0x0000000000000000
0x7fffb800d1c0:	0x6172752f7665642f	0x000000006d6f646e
0x7fffb800d1d0:	0x0000000000000000	0x0000000000000000
pwndbg> x/xs 0x7fffb800d1c0
0x7fffb800d1c0:	"/dev/urandom"
pwndbg> 
```

This means that you can search for the string `/dev/urandom` in the core dump. Once you find the address, the encryption key can be seen near it. 

Encryption key found in the core dump:

```
0xb3, 0x89, 0xae, 0x52, 0x8f, 0x9a, 0x34, 0xbd,
0x98, 0x35, 0x59, 0x9b, 0x97, 0x66, 0x85, 0x1b,
0x82, 0xb4, 0x25, 0x80, 0xb7, 0x20, 0xa3, 0x18,
```

### Block cipher mode

The last piece of puzzle is the hardest part. Since DES is block cipher, you need to figure out the block cipher mode. Again, there are many ways to achieve the goal. First, you can rule out CBC mode because file sizes are not a multiple of 8. This leaves CFB, OFB, CTR, and GCM.

For now, let's digress a little and trace some interesting variables. First, examine the assembly code from `0x2233C5` to `0x22346D`:

```
.text:00000000002233C5 loc_2233C5:                             ; DATA XREF: sub_222A30+987↑o
.text:00000000002233C5                 test    rax, rax
.text:00000000002233C8                 jnz     loc_222B04
.text:00000000002233CE                 mov     r14, [rsp+2D8h+var_280]
.text:00000000002233D3                 mov     rdi, r14
.text:00000000002233D6                 call    sub_21097B
.text:00000000002233DB                 mov     rdi, r14
.text:00000000002233DE                 call    sub_21097B
.text:00000000002233E3                 push    48h ; 'H'
.text:00000000002233E5                 pop     rdi
.text:00000000002233E6                 call    sub_212FDD
.text:00000000002233EB                 mov     rbp, rax
.text:00000000002233EE                 push    8
.text:00000000002233F0                 pop     rdi
.text:00000000002233F1                 call    sub_212FDD
.text:00000000002233F6                 mov     rbx, rax
.text:00000000002233F9                 mov     rax, [rsp+2D8h+var_238]
.text:0000000000223401                 mov     rax, [rax]
.text:0000000000223404                 mov     [rbx], rax
.text:0000000000223407                 mov     edi, 200h
.text:000000000022340C                 call    sub_212FDD
.text:0000000000223411                 mov     rcx, rax
.text:0000000000223414                 mov     [rbp+0], r14
.text:0000000000223418                 mov     rax, [rsp+2D8h+var_120]
.text:0000000000223420                 mov     [rbp+8], rax
.text:0000000000223424                 mov     [rbp+10h], rbx
.text:0000000000223428                 movaps  xmm0, cs:xmmword_2007B0
.text:000000000022342F                 movups  xmmword ptr [rbp+18h], xmm0
.text:0000000000223433                 mov     [rsp+2D8h+var_148], rcx
.text:000000000022343B                 mov     [rbp+28h], rcx
.text:000000000022343F                 movaps  xmm0, cs:xmmword_200690
.text:0000000000223446                 movups  xmmword ptr [rbp+30h], xmm0
.text:000000000022344A                 mov     [rsp+2D8h+var_140], rbp
.text:0000000000223452                 and     qword ptr [rbp+40h], 0
.text:0000000000223457                 lea     rbx, [rsp+2D8h+var_230]
.text:000000000022345F                 lea     rax, loc_22346D
.text:0000000000223466                 mov     [rbx+8], rax
.text:000000000022346A                 xor     rax, rax
```

The pseudo c code:

```c
...
v101 = sub_212FDD(72LL);
v102 = (_QWORD *)sub_212FDD(8LL);
*v102 = *v213;
v103 = sub_212FDD(512LL);
*(_QWORD *)v101 = v100;
*(_QWORD *)(v101 + 8) = v241;
*(_QWORD *)(v101 + 16) = v102;
*(_OWORD *)(v101 + 24) = xmmword_2007B0;
...
```

You might find out that `v101` is generated from `sub_212FDD` and subsequently called by `sub_21FCCB`. Since you already know that `sub_21FCCB` is the cryptographic random number generator, you can assume that `v101` stores the initial vector iv (Well, where else is `sub_21FCCB` needed besides generating key and iv ?).

Here, you know that the iv size is 8, so you can safely rule out GCM mode because the iv (nonce) size does not match (GCM mode requires 12 bytes nonce).

Next, trace the variable `v101`. This variable becomes `v237`, then `v203` , then `v152`, then `v115`. In the end, you'll land on somewhere near `0x22390E` and `0x22394B`. The assembly at `0x22393B` contains the xor operation between `v209`(perhaps the destination) and `v115` (perhaps the iv). The decompiled pseudo code is as follows:

```c
while ( v155 != v156 )
  {

    if ( v114 == v156 || v113 == v156 || v9 == v156 )
      goto LABEL_203;
    v17 = v208;
    *(_BYTE *)(v208 + v156) = *(_BYTE *)(v209 + v156) ^ *(_BYTE *)(v115 + v22 + v156);
    ++v156;
  }
```

Observe that `v209` is continually xored by a known variable `v115`. There's no encryption happening in between. This means that CFB is possible because they rely on the previously calculated ciphertext.

Alternatively, you can try decrypting files in OFB, CTR mode and see if the decrypted output makes sense. At the end of the day, you'll find out that only CTR mode generates plaintext files that make sense.

## Decrypt the directory

Now you got everything. Write a script to decode `flаg.txt` and `rickroll.jpg.qq`. If nothing goes wrong, you'll spot the flag in these two files. ~~Unless you want to get rickrolled, do not decrypt `cute_kitten.mkv` or `Wallpaper.jpg`~~

> Side note. Did anybody notice that the `а` in `flаg` is a cyrillic letter...?!

## Flag

```
hitcon{always_gonna_make_you_cry_always_gonna_say_goodbye}
```
