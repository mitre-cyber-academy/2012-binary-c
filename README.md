Binary exploits 200:

The user is presented with a binary. It won't run on their system.

Running the 'file' command against it reveals that it is indeed a linux ELF binary, but it's compiled for ARM...

Two expected responses:
1: The team will look for and build a simulated ARM environment to run the binary in (such as qemu)
2: The team will find the appropriate dissasembly tool, and pull the flag out by hand (the easier way)
    They will most likely objdump. They will need to download the appropriate version (ex: "apt-get install binutils-arm-linux-gnueabi")

The flag is XORed in the binary, along with 3 other dummy strings of the same length. There are 8 possible keys also stored in the binary file.

The program loops through the keys on only the real flag (if they notice that, they can disregard the others) and performs a strncmp against the first three letters of decrypted flag (nothing they don't already know). If the string matches (we found the right key), it prints the flag.

Teams will need to search through the binary, locate the possible flags and keys as well as the main and the crypt function. After analyzing it, they should: determine which string is the flag, locate the set of possible keys, and recognized the XOR cipher performed against them.

If they can pull that information out of the binary, they can perform the XOR against the string for each key and eventually find the right one.

Solution:
(note, I'm running on a mac, the commands may be slightly different for different a OS)

First, view the .rodata to view the flags that are used:
arm-none-eabi-objdump -s -j .rodata binary200

binary200:     file format elf32-littlearm

Contents of section .rodata:
 124f8 4d434100 596f7572 20666c61 673a2025  MCA.Your flag: %
 12508 73000000 382e342c 34323523 2d2e3235  s...8.4,425#-.25
 12518 00000000 3f3e215c 25232830 3630383f  ....?>!\%#(0608?
 12528 00000000 2c22204c 57515257 56272725  ....," LWQRWV''%
 12538 00000000 3421385c 32373038 3d4b5659  ....4!8\2708=KVY
 12548 00000000 63737172 61666f68 60a80100  ....csqrafoh`...
 12558 43000000 3a747400 20202020 20202020  C...:tt.
 ...

 Then disassemble to binary:
 arm-none-eabi-objdump -d binary200 > bin200.out

 In there you can find the main and crypt functions since I didn't strip anything.

In here we have to dig through the assembly until we can determine what it does
First things first, we see the 4 variables we care about:

    82c8:       e59f20ec        ldr     r2, [pc, #236]  ; 83bc <main+0x110>
    82cc:       e24b3014        sub     r3, fp, #20
    82d0:       e8920007        ldm     r2, {r0, r1, r2}
    82d4:       e8830007        stm     r3, {r0, r1, r2}
    82d8:       e59f20e0        ldr     r2, [pc, #224]  ; 83c0 <main+0x114>
    82dc:       e24b3020        sub     r3, fp, #32
    82e0:       e8920007        ldm     r2, {r0, r1, r2}
    82e4:       e8830007        stm     r3, {r0, r1, r2}
    82e8:       e59f20d4        ldr     r2, [pc, #212]  ; 83c4 <main+0x118>
    82ec:       e24b302c        sub     r3, fp, #44     ; 0x2c
    82f0:       e8920007        ldm     r2, {r0, r1, r2}
    82f4:       e8830007        stm     r3, {r0, r1, r2}
    82f8:       e59f20c8        ldr     r2, [pc, #200]  ; 83c8 <main+0x11c>
    82fc:       e24b3038        sub     r3, fp, #56     ; 0x38
    8300:       e8920007        ldm     r2, {r0, r1, r2}
    8304:       e8830007        stm     r3, {r0, r1, r2}
    8308:       e59f30bc        ldr     r3, [pc, #188]  ; 83cc <main+0x120>



000082ac <main>:

    83bc:       0001250c        .word   0x0001250c
    83c0:       0001251c        .word   0x0001251c
    83c4:       0001252c        .word   0x0001252c
    83c8:       0001253c        .word   0x0001253c

    83cc:       0001254c        .word   0x0001254c
    83d0:       000124f8        .word   0x000124f8
    83d4:       000124fc        .word   0x000124fc

looking at 1250c, 1251c, 1252c, 1253c, we have four strings:

1: 382e342c 34323523 2d2e3235   (8.4,425#-.25)
2: 3f3e215c 25232830 3630383f   (?>!\%#(0608?)
3: 2c22204c 57515257 56272725   (," LWQRWV''%)
4: 3421385c 32373038 3d4b5659   (4!8\2708=KVY)

and our keys:

63737172 61666f68    (csqrafoh)


Next is the logic to loop through every key, decrypt the flag, and compare it against a string:

    8328:       e3a03000        mov     r3, #0
    832c:       e50b3008        str     r3, [fp, #-8]
    8330:       ea00001a        b       83a0 <main+0xf4>
    8334:       e3e0303b        mvn     r3, #59 ; 0x3b
    8338:       e51b2008        ldr     r2, [fp, #-8]
    833c:       e24b1004        sub     r1, fp, #4
    8340:       e0812002        add     r2, r1, r2
    8344:       e0823003        add     r3, r2, r3
    8348:       e5d33000        ldrb    r3, [r3]
    834c:       e24b102c        sub     r1, fp, #44     ; 0x2c
    8350:       e24b2050        sub     r2, fp, #80     ; 0x50
    8354:       e1a00001        mov     r0, r1
    8358:       e1a01002        mov     r1, r2
    835c:       e1a02003        mov     r2, r3
    8360:       ebffff9f        bl      81e4 <crypt>
    8364:       e24b3050        sub     r3, fp, #80     ; 0x50
    8368:       e1a00003        mov     r0, r3
    836c:       e59f105c        ldr     r1, [pc, #92]   ; 83d0 <main+0x124>
    8370:       e3a02003        mov     r2, #3
    8374:       eb000104        bl      878c <strncmp>
    8378:       e1a03000        mov     r3, r0
    837c:       e3530000        cmp     r3, #0
    8380:       1a000003        bne     8394 <main+0xe8>
    8384:       e24b3050        sub     r3, fp, #80     ; 0x50
    8388:       e59f0044        ldr     r0, [pc, #68]   ; 83d4 <main+0x128>
    838c:       e1a01003        mov     r1, r3
    8390:       eb0000d5        bl      86ec <printf>
    8394:       e51b3008        ldr     r3, [fp, #-8]
    8398:       e2833001        add     r3, r3, #1
    839c:       e50b3008        str     r3, [fp, #-8]
    83a0:       e51b3008        ldr     r3, [fp, #-8]
    83a4:       e3530008        cmp     r3, #8
    83a8:       9affffe1        bls     8334 <main+0x88>


First we see i get set,

we set i=0, push it onto the stack, and jump to our for loop comparison:
    8328:       e3a03000        mov     r3, #0
    832c:       e50b3008        str     r3, [fp, #-8]
    8330:       ea00001a        b       83a0 <main+0xf4>


The comparison loads the i value off the stack, compares it to 8, and jumps into the for loop if it is less than to 8

    83a0:       e51b3008        ldr     r3, [fp, #-8]
    83a4:       e3530008        cmp     r3, #8
    83a8:       9affffe1        bls     8334 <main+0x88>


Inside the loop, we fill registers 0, 1, and 2 with the third encrypted flag, our decrypted flag, and keys[i]:
    8334:       e3e0303b        mvn     r3, #59 ; 0x3b
    8338:       e51b2008        ldr     r2, [fp, #-8]
    833c:       e24b1004        sub     r1, fp, #4
    8340:       e0812002        add     r2, r1, r2
    8344:       e0823003        add     r3, r2, r3
    8348:       e5d33000        ldrb    r3, [r3]
    834c:       e24b102c        sub     r1, fp, #44     ; 0x2c
    8350:       e24b2050        sub     r2, fp, #80     ; 0x50
    8354:       e1a00001        mov     r0, r1
    8358:       e1a01002        mov     r1, r2
    835c:       e1a02003        mov     r2, r3

and jump to the crypt function:
    8360:       ebffff9f        bl      81e4 <crypt>


The flag is then compared to [main+0x124], or 4d4341  (MCA):


    8364:       e24b3050        sub     r3, fp, #80     ; 0x50
    8368:       e1a00003        mov     r0, r3
    836c:       e59f105c        ldr     r1, [pc, #92]   ; 83d0 <main+0x124>
    8370:       e3a02003        mov     r2, #3
    8374:       eb000104        bl      878c <strncmp>

If no match, jump ahead:
    8378:       e1a03000        mov     r3, r0
    837c:       e3530000        cmp     r3, #0
    8380:       1a000003        bne     8394 <main+0xe8>

If they match, load the value at main+0x128 (596f7572 20666c61 673a2025     Your flag: %)
and the flag into registers 0 and 1, and call printf
    8384:       e24b3050        sub     r3, fp, #80     ; 0x50
    8388:       e59f0044        ldr     r0, [pc, #68]   ; 83d4 <main+0x128>
    838c:       e1a01003        mov     r1, r3
    8390:       eb0000d5        bl      86ec <printf>

Increment i by 1 and try again!
    8394:       e51b3008        ldr     r3, [fp, #-8]
    8398:       e2833001        add     r3, r3, #1
    839c:       e50b3008        str     r3, [fp, #-8]



As for the crypt function....:
    81e4:       e92d4800        push    {fp, lr}
    81e8:       e28db004        add     fp, sp, #4
    81ec:       e24dd018        sub     sp, sp, #24
    81f0:       e50b0010        str     r0, [fp, #-16]
    81f4:       e50b1014        str     r1, [fp, #-20]
    81f8:       e1a03002        mov     r3, r2
    81fc:       e54b3015        strb    r3, [fp, #-21]
    8200:       e51b0010        ldr     r0, [fp, #-16]
    8204:       eb000148        bl      872c <strlen>
    8208:       e1a03000        mov     r3, r0
    820c:       e50b300c        str     r3, [fp, #-12]
    8210:       e3a03000        mov     r3, #0
    8214:       e50b3008        str     r3, [fp, #-8]
    8218:       e3a03000        mov     r3, #0
    821c:       e50b3008        str     r3, [fp, #-8]
    8220:       ea000015        b       827c <crypt+0x98>
    8224:       e51b2014        ldr     r2, [fp, #-20]
    8228:       e51b3008        ldr     r3, [fp, #-8]
    822c:       e0823003        add     r3, r2, r3
    8230:       e51b1010        ldr     r1, [fp, #-16]
    8234:       e51b2008        ldr     r2, [fp, #-8]
    8238:       e0812002        add     r2, r1, r2
    823c:       e5d22000        ldrb    r2, [r2]
    8240:       e5c32000        strb    r2, [r3]
    8244:       e51b2014        ldr     r2, [fp, #-20]
    8248:       e51b3008        ldr     r3, [fp, #-8]
    824c:       e0823003        add     r3, r2, r3
    8250:       e51b1014        ldr     r1, [fp, #-20]
    8254:       e51b2008        ldr     r2, [fp, #-8]
    8258:       e0812002        add     r2, r1, r2
    825c:       e5d21000        ldrb    r1, [r2]
    8260:       e55b2015        ldrb    r2, [fp, #-21]
    8264:       e0212002        eor     r2, r1, r2
    8268:       e20220ff        and     r2, r2, #255    ; 0xff
    826c:       e5c32000        strb    r2, [r3]
    8270:       e51b3008        ldr     r3, [fp, #-8]
    8274:       e2833001        add     r3, r3, #1
    8278:       e50b3008        str     r3, [fp, #-8]
    827c:       e51b2008        ldr     r2, [fp, #-8]
    8280:       e51b300c        ldr     r3, [fp, #-12]
    8284:       e1520003        cmp     r2, r3
    8288:       3affffe5        bcc     8224 <crypt+0x40>
    828c:       e51b2014        ldr     r2, [fp, #-20]
    8290:       e51b3008        ldr     r3, [fp, #-8]
    8294:       e0823003        add     r3, r2, r3
    8298:       e3a0200a        mov     r2, #10
    829c:       e5c32000        strb    r2, [r3]
    82a0:       e24bd004        sub     sp, fp, #4
    82a4:       e8bd4800        pop     {fp, lr}
    82a8:       e12fff1e        bx      lr






we can see the call to strlen, we can see the results of that stored to the stack, and we see i set to 0 and stored to the stack:
    8200:       e51b0010        ldr     r0, [fp, #-16]
    8204:       eb000148        bl      872c <strlen>
    8208:       e1a03000        mov     r3, r0
    820c:       e50b300c        str     r3, [fp, #-12]
    8210:       e3a03000        mov     r3, #0
    8214:       e50b3008        str     r3, [fp, #-8]
    8218:       e3a03000        mov     r3, #0
    821c:       e50b3008        str     r3, [fp, #-8]

    (twice because I declared it as 0 and then again in the for loop right after...)

As before, we see the jump to the for loop comparison, and the jump back to the logic

    8220:       ea000015        b       827c <crypt+0x98>
    ...
    827c:       e51b2008        ldr     r2, [fp, #-8]
    8280:       e51b300c        ldr     r3, [fp, #-12]
    8284:       e1520003        cmp     r2, r3
    8288:       3affffe5        bcc     8224 <crypt+0x40>

The logic inside copies originalMessage[i] to codedMessage[i] and XORs it with the key:
    8224:       e51b2014        ldr     r2, [fp, #-20]
    8228:       e51b3008        ldr     r3, [fp, #-8]
    822c:       e0823003        add     r3, r2, r3
    8230:       e51b1010        ldr     r1, [fp, #-16]
    8234:       e51b2008        ldr     r2, [fp, #-8]
    8238:       e0812002        add     r2, r1, r2
    823c:       e5d22000        ldrb    r2, [r2]
    8240:       e5c32000        strb    r2, [r3]
    8244:       e51b2014        ldr     r2, [fp, #-20]
    8248:       e51b3008        ldr     r3, [fp, #-8]
    824c:       e0823003        add     r3, r2, r3
    8250:       e51b1014        ldr     r1, [fp, #-20]
    8254:       e51b2008        ldr     r2, [fp, #-8]
    8258:       e0812002        add     r2, r1, r2
    825c:       e5d21000        ldrb    r1, [r2]
    8260:       e55b2015        ldrb    r2, [fp, #-21]
    8264:       e0212002        eor     r2, r1, r2
    8268:       e20220ff        and     r2, r2, #255    ; 0xff
    826c:       e5c32000        strb    r2, [r3]

Increment i and continue:
    8270:       e51b3008        ldr     r3, [fp, #-8]
    8274:       e2833001        add     r3, r3, #1
    8278:       e50b3008        str     r3, [fp, #-8]





Hopefully, the teams will be able to determine they care about one encrypted flag:
2c22204c 57515257 56272725  (," LWQRWV''%)

and a set of 8 keys:

c   (0x63)
s   (0x73)
q   (0x71)
r   (0x72)
a   (0x61)
f   (0x66)
o   (0x6F)
h   (0x68)

It will be up to them to write a script that can  XOR the string against each key, or find a calculator somewhere, etc.
They will eventually determine the correct key is 'a', or 0x61, yielding the flag: MCA-60367FFD



