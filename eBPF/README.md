# 关于 eBPF


关于 eBPF 指令集的[官方文档位][1] 于 Linux repo 的 Networking 中, 实际上也能说明它原来是设计用于网络过滤的嘛.

关于设计过程的一些 QA 也有很有价值的记录.

本篇是对自己近几个月来断断续续学习 BPF 的笔记的整理.
持续更新

@iAklis (aka. aklis chen)

## 指令编码 Instruction encoding


首先明确 eBPF 程序是一系列的**64位**指令. 每个指令都是以主机字节序编码.但实际上字节序没有啥影响.


所以 eBPF 指令都拥有相同的基本规格:

```
    msb                                                                lsb
    +--------------------------------+----------------+----+----+--------+
    |immediate                       |offset          |src |dst |opcode  |
    +--------------------------------+----------------+----+----+--------+
     |<-------------32------------->| |<-----16----->|

```

从最低有效位到最高有效位划分成五个部分,分别是:

 - 8 bit opcode
 - 4 bit destination register (dst)
 - 4 bit source register (src)
 - 16 bit offset
 - 32 bit immediate (imm 立即数)

大多数指定不需要用完所有的比特位, 没有用到的部份都应该置0



## OPCODE

上文介绍了 opcode 在一条指令中只占了低八位.
这低八位也有对应区域划分一个 opcode 的结构.

指令的低三位,同时也是 opcode 部份的低三位表示了当前指令的分类.
换句话说,同一种类型的 opcode 都低三位都是一样的.
同时也限制了最多有八类指令.

> 4 + 2 + 1 + 1 = 8

在指令视角下总共有以下八类指令:

| Classic BPF classes: ||     eBPF classes: ||
| --       |   ---         |    --  |  -          |
|BPF_LD  |  0x00       |   BPF_LD  |  0x00 |
|BPF_LDX |  0x01      |     BPF_LDX  |  0x01 |
|BPF_ST   | 0x02       |   BPF_ST   | 0x02 |
|BPF_STX  | 0x03       |   BPF_STX  | 0x03 |
|BPF_ALU  | 0x04       |   BPF_ALU  | 0x04 |
|BPF_JMP  | 0x05      |    BPF_JMP  | 0x05 |
|BPF_RET  | 0x06      |    `BPF_JMP32` | 0x06 |
|BPF_MISC |  0x07      |    `BPF_ALU64` | 0x07 |

LD/LDX/ST/STX opcode structure:

    msb      lsb
    +---+--+---+
    |mde|sz|cls|
    +---+--+---+

`sz` 表示目标内存的大小.
`mde` 表示内存的访问模式.
在 uBPF (Userspace eBPF VM) 中, `mde` 能且只能是 `"MEM"`

ALU/ALU64/JMP opcode structure:

    msb      lsb
    +----+-+---+
    |op  |s|cls|
    +----+-+---+


在运算和跳转类型的 opcode 中, `s` (就是低位起第4位)如果是 `0`,那么源操作数(source operand)就是立即数`imm`. 如果是 `1`, 那么源操作数就是 `src`.

`op` 代表的 4bit 钦定了由 ALU 还是 分支操作.


## ALU Instructions

### 64-bit

64-bit ALU 运算指令, opcode 的低三位都是 `111`, 都属于 BPF_ALU64.

Order  |  Opcode(2)  | Opcode | Mnemonic      | Pseudocode
-------|-------------|--------|---------------|-----------------------
1      | 0b0000 0111 | 0x07   | add dst, imm  | dst += imm
2      | 0b0000 1111 | 0x0f   | add dst, src  | dst += src
3      | 0b0001 0111 | 0x17   | sub dst, imm  | dst -= imm
4      | 0b0001 1111 | 0x1f   | sub dst, src  | dst -= src
5      | 0b0010 0111 | 0x27   | mul dst, imm  | dst *= imm
6      | 0b0010 1111 | 0x2f   | mul dst, src  | dst *= src
7      | 0b0011 0111 | 0x37   | div dst, imm  | dst /= imm
8      | 0b0011 1111 | 0x3f   | div dst, src  | dst /= src
9      | 0b0100 0111 | 0x47   | or dst, imm   | dst \|= imm
10     | 0b0100 1111 | 0x4f   | or dst, src   | dst \|= src
11     | 0b0101 0111 | 0x57   | and dst, imm  | dst &= imm
12     | 0b0101 1111 | 0x5f   | and dst, src  | dst &= src
13     | 0b0110 0111 | 0x67   | lsh dst, imm  | dst <<= imm
14     | 0b0110 1111 | 0x6f   | lsh dst, src  | dst <<= src
15     | 0b0111 0111 | 0x77   | rsh dst, imm  | dst >>= imm (logical 逻辑)
16     | 0b0111 1111 | 0x7f   | rsh dst, src  | dst >>= src (logical)
17     | 0b1000 0111 | 0x87   | neg dst       | dst = -dst
18     | 0b1001 0111 | 0x97   | mod dst, imm  | dst %= imm
19     | 0b1001 1111 | 0x9f   | mod dst, src  | dst %= src
20     | 0b1010 0111 | 0xa7   | xor dst, imm  | dst ^= imm
21     | 0b1010 1111 | 0xaf   | xor dst, src  | dst ^= src
22     | 0b1011 0111 | 0xb7   | mov dst, imm  | dst = imm
23     | 0b1011 1111 | 0xbf   | mov dst, src  | dst = src
24     | 0b1100 0111 | 0xc7   | arsh dst, imm | dst >>= imm (arithmetic 算术)
25     | 0b1100 1111 | 0xcf   | arsh dst, src | dst >>= src (arithmetic)


### 32-bit 指令

32-bit ALU 运算指令, opcode 的低三位都是 `100`, 都属于 BPF_ALU.

32bit 指令使用和64位指定一样的结构, 从形式上就是 64bit 在兼容 32bit.
32bit 指令仅使用操作数的低32bit 和 目标寄存器的 高32bit.
每一个 ALU 32-bit 指令都有对应的 64-bit 指令.

Order  |  Opcode(2)  | Opcode | Mnemonic        | Pseudocode
-------|-------------|--------|-----------------|------------------------------
1      | 0b0000 0100 | 0x04   | add32 dst, imm  | dst += imm
2      | 0b0000 1100 | 0x0c   | add32 dst, src  | dst += src
3      | 0b0001 0100 | 0x14   | sub32 dst, imm  | dst -= imm
4      | 0b0001 1100 | 0x1c   | sub32 dst, src  | dst -= src
5      | 0b0010 0100 | 0x24   | mul32 dst, imm  | dst *= imm
6      | 0b0010 1100 | 0x2c   | mul32 dst, src  | dst *= src
7      | 0b0011 0100 | 0x34   | div32 dst, imm  | dst /= imm
8      | 0b0011 1100 | 0x3c   | div32 dst, src  | dst /= src
9      | 0b0100 0100 | 0x44   | or32 dst, imm   | dst \|= imm
10     | 0b0100 1100 | 0x4c   | or32 dst, src   | dst \|= src
11     | 0b0101 0100 | 0x54   | and32 dst, imm  | dst &= imm
12     | 0b0101 1100 | 0x5c   | and32 dst, src  | dst &= src
13     | 0b0110 0100 | 0x64   | lsh32 dst, imm  | dst <<= imm
14     | 0b0110 1100 | 0x6c   | lsh32 dst, src  | dst <<= src
15     | 0b0111 0100 | 0x74   | rsh32 dst, imm  | dst >>= imm (logical)
16     | 0b0111 0100 | 0x7c   | rsh32 dst, src  | dst >>= src (logical)
17     | 0b1000 0100 | 0x84   | neg32 dst       | dst = -dst
18     | 0b1001 0100 | 0x94   | mod32 dst, imm  | dst %= imm
19     | 0b1001 1100 | 0x9c   | mod32 dst, src  | dst %= src
20     | 0b1010 0100 | 0xa4   | xor32 dst, imm  | dst ^= imm
21     | 0b1010 1100 | 0xac   | xor32 dst, src  | dst ^= src
22     | 0b1011 0100 | 0xb4   | mov32 dst, imm  | dst = imm
23     | 0b1011 1100 | 0xbc   | mov32 dst, src  | dst = src
24     | 0b1100 0100 | 0xc4   | arsh32 dst, imm | dst >>= imm (arithmetic)
25     | 0b1100 1100 | 0xcc   | arsh32 dst, src | dst >>= src (arithmetic)


### ALU补充

如果 ClS 属于 BPF_ALU 或者 BPF_ALU64 ,那么 opcode 一定是以下的某一种.
上面 64/32 都是属于算术运算, 分别是25个. 是用ALU指令配合 `sz` 和 `mde` 衍生出来的. 

以下汇编有效位是上四位.
```
  BPF_ADD   0x00
  BPF_SUB   0x10
  BPF_MUL   0x20
  BPF_DIV   0x30
  BPF_OR    0x40
  BPF_AND   0x50
  BPF_LSH   0x60
  BPF_RSH   0x70
  BPF_NEG   0x80
  BPF_MOD   0x90
  BPF_XOR   0xa0
  BPF_MOV   0xb0  /* eBPF only: mov reg to reg */
  BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
  BPF_END   0xd0  /* eBPF only: endianness conversion */
```

(12 * 4) + 2 = 50
50 + BPF_END 总共有 51 种 ALU类型的指令.


## Branch Instructions

分支跳转指令 opcode 低三位都是 `101`
同时分跳转指令更接近于 ALU 指令, 低第4位用来区分源操作数是`imm`还是`src`. 这一点上和内存操作指令不同.



Order  |  Opcode(2)  | Opcode | Mnemonic            | Pseudocode
-------|-------------|--------|---------------------|------------------------
1      | 0b0000 0101 | 0x05   | ja +off             | PC += off
2      | 0b0001 0101 | 0x15   | jeq dst, imm, +off  | PC += off if dst == imm
3      | 0b0001 1101 | 0x1d   | jeq dst, src, +off  | PC += off if dst == src
4      | 0b0000 0101 | 0x25   | jgt dst, imm, +off  | PC += off if dst > imm
5      | 0b0010 1101 | 0x2d   | jgt dst, src, +off  | PC += off if dst > src
6      | 0b0011 0101 | 0x35   | jge dst, imm, +off  | PC += off if dst >= imm
7      | 0b0011 1101 | 0x3d   | jge dst, src, +off  | PC += off if dst >= src
8      | 0b1010 0101 | 0xa5   | jlt dst, imm, +off  | PC += off if dst < imm
9      | 0b1010 1101 | 0xad   | jlt dst, src, +off  | PC += off if dst < src
10     | 0b1011 0101 | 0xb5   | jle dst, imm, +off  | PC += off if dst <= imm
11     | 0b1011 1101 | 0xbd   | jle dst, src, +off  | PC += off if dst <= src
12     | 0b0100 0101 | 0x45   | jset dst, imm, +off | PC += off if dst & imm
13     | 0b0100 1101 | 0x4d   | jset dst, src, +off | PC += off if dst & src
14     | 0b0101 0101 | 0x55   | jne dst, imm, +off  | PC += off if dst != imm
15     | 0b0101 1101 | 0x5d   | jne dst, src, +off  | PC += off if dst != src
16     | 0b0110 0101 | 0x65   | jsgt dst, imm, +off | PC += off if dst > imm (signed)
17     | 0b0110 1101 | 0x6d   | jsgt dst, src, +off | PC += off if dst > src (signed)
18     | 0b0111 0101 | 0x75   | jsge dst, imm, +off | PC += off if dst >= imm (signed)
19     | 0b0111 1101 | 0x7d   | jsge dst, src, +off | PC += off if dst >= src (signed)
20     | 0b1100 0101 | 0xc5   | jslt dst, imm, +off | PC += off if dst < imm (signed)
21     | 0b1100 1101 | 0xcd   | jslt dst, src, +off | PC += off if dst < src (signed)
22     | 0b1101 0101 | 0xd5   | jsle dst, imm, +off | PC += off if dst <= imm (signed)
23     | 0b1101 1101 | 0xdd   | jsle dst, src, +off | PC += off if dst <= src (signed)
24     | 0b0100 0101 | 0x85   | call imm            | Function call
25     | 0b1001 0101 | 0x95   | exit                | return r0


### JMP 补充
```
BPF_JA    0x00  /* BPF_JMP only */
BPF_JEQ   0x10
BPF_JGT   0x20
BPF_JGE   0x30
BPF_JSET  0x40
BPF_JNE   0x50  /* eBPF only: jump != */
BPF_JSGT  0x60  /* eBPF only: signed '>' */
BPF_JSGE  0x70  /* eBPF only: signed '>=' */
BPF_CALL  0x80  /* eBPF BPF_JMP only: function call */
BPF_EXIT  0x90  /* eBPF BPF_JMP only: function return */
BPF_JLT   0xa0  /* eBPF only: unsigned '<' */
BPF_JLE   0xb0  /* eBPF only: unsigned '<=' */
BPF_JSLT  0xc0  /* eBPF only: signed '<' */
BPF_JSLE  0xd0  /* eBPF only: signed '<=' */
```

( 14-3 ) * 2 + 3 = 22
11 * 2 + 3 = 25

51 + 25 = 76

## Memory Instructions

内存操作指令, opcode 同样有八位

这八位同时也划分成了三个部分.

 - 3 bit opcode 类型
 - 2 bit 目标内存大小
 - 3 bit 内存访问模式

ld 低三位都是 `000`.
ldx 低三位都是 `001`.
st 低三位都是 `010`.
stx 低三位都是 `011`.

与classic BPF指令不同, eBPF 有通用的 load/store 操作指令格式:

```
BPF_MEM | <size> | BPF_STX:  *(size *) (dst_reg + off) = src_reg
BPF_MEM | <size> | BPF_ST:   *(size *) (dst_reg + off) = imm32
BPF_MEM | <size> | BPF_LDX:  dst_reg = *(size *) (src_reg + off)
BPF_XADD | BPF_W  | BPF_STX: lock xadd *(u32 *)(dst_reg + off16) += src_reg
BPF_XADD | BPF_DW | BPF_STX: lock xadd *(u64 *)(dst_reg + off16) += src_reg
```

低三位 | - | 助记 | 能组合的指令 | 备注 |
----| -- | ----| -- | --|
000 | 0x00 | BPF_LD | lddw, ldabsw, ldabsh, ldabsb, ldabsdw, ldindw, ldindh, ldindb, ldinddw | 9 |
001 | 0x01 |BPF_LDX |ldxw, ldxh, ldxb, ldxdw | 4 |
010 | 0x02 |BPF_ST | stw, sth, stb, stdw | 4 |
011 | 0x03 | BPF_STX | stxw, stxh, stxb, stxdw | 4 |


sz | - | 助记 |  |
---| -- | --| -- |
00 | *(uint32_t *) | BPF_W | word
01 | *(uint16_t *) | BPF_H | half word
10 | *(uint8_t *)  | BPF_B | byte
11 | *(uint64_t *) | BPF_DW | eBPF only, double word
 
 
mde | -    | 助记      | 1 |
--- | ---- | --------- | - |
000 | 0x00 | `BPF_IMM`   | used for 32-bit mov in classic BPF, and 64-bit in eBPF |
001 | 0x20 | `BPF_ABS`   | - |
010 | 0x40 | `BPF_IND`   | - |
011 | 0x60 | `BPF_MEM`    | - |
100 | 0x80 | BPF_LEN   | classic BPF only, reserved in eBPF |
101 | 0xa0 | BPF_MSH   | classic BPF only, reserved in eBPF |
110 | 0xc0 | BPF_XADD  | eBPF only, exclusive add |


eBPF 有两个非通用的(non-generic)的指令:
`(BPF_ABS | <size> | BPF_LD)` and
`(BPF_IND | <size> | BPF_LD)`
用来访问数据包.


### Load/Storage 补充

TODO
  


### Byteswap instructions

字节交换指令, opcode 只有 `0xd4` 和 `0xdc` 两种.

Opcode           | Mnemonic | Pseudocode
-----------------|----------|-------------------
0xd4 (imm == 16) | le16 dst | dst = htole16(dst)
0xd4 (imm == 32) | le32 dst | dst = htole32(dst)
0xd4 (imm == 64) | le64 dst | dst = htole64(dst)
0xdc (imm == 16) | be16 dst | dst = htobe16(dst)
0xdc (imm == 32) | be32 dst | dst = htobe32(dst)
0xdc (imm == 64) | be64 dst | dst = htobe64(dst)



## 寄存器

 On 64-bit architectures all register map to HW registers one to one. For
  example, x86_64 JIT compiler can map them as ...

    R0 - rax
    R1 - rdi
    R2 - rsi
    R3 - rdx
    R4 - rcx
    R5 - r8
    R6 - rbx
    R7 - r13
    R8 - r14
    R9 - r15
    R10 - rbp

  ... since x86_64 ABI mandates rdi, rsi, rdx, rcx, r8, r9 for argument passing
  and rbx, r12 - r15 are callee saved.
  



## 函数调用

在调用内核函数之前, 内部的BPF程序需要先把函数参数放到 R1 到 R5 寄存器以满足调用约定.
之后**解释器**将从寄存器中获取它们并传递内核功能.

如果 R1 到 R5 寄存器被映身到给定的体系结构上的 CPU 的寄存器, JIT 编译器就不需要额外的操作.

函数参数将存放于正确的寄存器中, 同时 BPF_CALL 这一条指令也会被即时编译成CPU的 call
指令. 这种函数调用约定就是因为不会有额外的性能损耗而受到青睐.

内核函数在调用后, `R1 - R5` 将被重置为`不可读`, 并且 R0 保存了 BPF 程序调用的 返回值 .


由于保存了 `R6 - R9` ,因此它的状态在整个调用过程中是被保留的.


以下函数:


```
  u64 f1() { return (*_f2)(1); }
  u64 f2(u64 a) { return f3(a + 1, a); }
  u64 f3(u64 a, u64 b) { return a - b; }
  
```
  GCC can compile f1, f3 into x86_64:
```
  f1:
    movl $1, %edi
    movq _f2(%rip), %rax
    jmp  *%rax
  f3:
    movq %rdi, %rax
    subq %rsi, %rax
    ret
```
  Function f2 in eBPF may look like:
```
  f2:
    bpf_mov R2, R1
    bpf_add R1, 1
    bpf_call f3
    bpf_exit

```
如果开启了 JIT 上面 f1 f3 的代码就几乎是顺序执行.

如果没有开JIT, f2就需要一次函数调用
https://godbolt.org/z/jbZP3b

```
unsigned long long f3(unsigned long long a, unsigned long long b) { return a - b; }
unsigned long long f2(unsigned long long a) { return f3(a + 1, a); }
unsigned long long f1() { return (*f2)(323); }
```


另一个例子

  
```
  
u64 bpf_filter(u64 ctx)
{
    return foo(ctx, 2, 3, 4, 5) + bar(ctx, 6, 7, 8, 9);
}
```

假设 foo 和 bar 是内核函数, 且其原型都是

```
u64 (*)(u64 arg1, u64
  arg2, u64 arg3, u64 arg4, u64 arg5);
```

它们的参数 **argX 都会被放入特定的寄存器**中, 并且把它们的返回值放入 `%rax`, 在 eBPF 中的 R0.

R0-R5是暂存寄存器, eBPF程序需要保留它们的内容以保证内核函数的调用约定.

开头

> bpf_mov R6, R1 /* save ctx */
    bpf_mov R2, 2
    bpf_mov R3, 3
    bpf_mov R4, 4
    bpf_mov R5, 5
    
结尾

>   bpf_mov R7, R0
bpf_mov R1, R6
    
  
  
Then the following internal BPF pseudo-program:
    
```
    bpf_mov R6, R1 /* save ctx */
    bpf_mov R2, 2
    bpf_mov R3, 3
    bpf_mov R4, 4
    bpf_mov R5, 5
    bpf_call foo
    bpf_mov R7, R0 /* save foo() return value */
    bpf_mov R1, R6 /* restore ctx for next call */
    bpf_mov R2, 6
    bpf_mov R3, 7
    bpf_mov R4, 8
    bpf_mov R5, 9
    bpf_call bar
    bpf_add R0, R7
    bpf_exit
```

  After JIT to x86_64 may look like:
```
    push %rbp
    mov %rsp,%rbp
    sub $0x228,%rsp
    mov %rbx,-0x228(%rbp)
    mov %r13,-0x220(%rbp)
    mov %rdi,%rbx
    mov $0x2,%esi
    mov $0x3,%edx
    mov $0x4,%ecx
    mov $0x5,%r8d
    callq foo
    mov %rax,%r13
    mov %rbx,%rdi
    mov $0x6,%esi
    mov $0x7,%edx
    mov $0x8,%ecx
    mov $0x9,%r8d
    callq bar
    add %r13,%rax
    mov -0x228(%rbp),%rbx
    mov -0x220(%rbp),%r13
    leaveq
    retq
```


# eBPF 的限制

新格式指的就是 eBPF. 也称`internal BPF`.

寄存器的数量从原始BPF也就是(cBPF)的 2个 到 eBPF 的 10个.

eBPF 程序最多只能有 4096 条指令, 并且只会调用固定数量的内核函数.

Original BPF and the new format are two operand instructions,
which helps to do one-to-one mapping between eBPF insn and x86 insn during JIT.

用于调用解释器功能的输入上下文指针ctx是通用的，其内容由特定的用例定义。 对于seccomp寄存器，R1指向seccomp_data，对于转换后的BPF过滤器，R1指向skb。
R1 的指向可能会变, 但都指向了符合 bpf prog 类型的 `上下文`


到目前为止总共实现 **87** 条 BPF 指令, 8bit 的 opcode 还有空位.


Some of them may use 16/24/32 byte encoding. New
instructions must be multiple of 8 bytes to preserve backward compatibility.


Internal BPF 是通用RISC指令集。 从原始BPF转换为`新格式`期间，并非使用每个寄存器和每个指令。

例如，套接字过滤器(socket filters)未使用`exclusive add`指令，但是跟踪过滤器(tracing filters )可能确实会维护事件计数器。

套接字过滤器也未使用寄存器R9，但是更复杂的过滤器可能用尽了寄存器，因此不得不求助于堆栈来存放操作数据。

出于实际原因，所有eBPF程序都只有一个参数`ctx`，即已经放在R1中（例如在`__bpf_prog_run()`启动时）和程序最多可以调用带有5个参数的内核函数。带有6个或更多参数的调用目前不支持，但是在将来可以根据需要取消这些限制.


## 验证

Linux 通过两个步骤来保证 eBPF 程序的安全性.

通过 DAG 检查来禁止任何的循环,还有额外的调用流程图验证.
特别是会检查是否存在不可达的指令.

第二步是模拟执行所有指令同时观察寄存器和栈上的变化.



load/store 指令操作的寄存器必须存放有效的指针类型数据,而且只能是 `PTR_TO_CTX`, `PTR_TO_MAP`, `PTR_TO_STACK`.


### 对 ctx 的访问限制

- 验证器回调ACL

如果某个寄存器比如 R1 保存的是 `PTR_TO_CTX` (即指向`struct bpf_context`).
一个回调(比如 `is_valid_access()`)就会被隐式地调用,来限制 eBPF 程序来访问且仅能访问当前结构体`struct bpf_context`的字段,同时`必须对齐`和指定`长度`.

```
bpf_ld R0 = *(u32 *)(R6 + 8)
```
如果 `R6=PTR_TO_CTX` , 通过 `is_valid_access()` 回调验证器就能验证 R6偏移8并且长度为4的区域是*可以*被访问的.

如果 `R6=PTR_TO_STACK` , 对于R6所指向的结构体的访问就必须被对齐. 同时栈地址是从高到低的,
所以[-MAX_BPF_STACK, 0) 的偏移都是可以被访问的.
在这个例子里面,偏移是8,所以它*不会*通过验证器的验证.

> The verifier will allow eBPF program to read data from stack only after
it wrote into it.



- 验证器将只允许 eBPF 程序在对堆栈写入内容后才允许读取内容.

```
bpf_ld R0 = *(u32 *)(R10 - 4)
```

R10 是只读寄存器, 并且指向 `PTR_TO_STACK`的读取偏移为 `-4`(小于0, 在范围内).
但由于没有对堆栈写入过内容,所以不能够读取`PTR_TO_STACK`上的内容.


## 寄存器跟踪

每个寄存器状态都有一个类型，该类型可以是NOT_INIT（尚未写入寄存器），SCALAR_VALUE（某些值不能用作指针）或指针类型。


| 指针类型 | |
|-|-|
| PTR_TO_CTX | Pointer to `bpf_context` |
|CONST_PTR_TO_MAP |Pointer to `struct bpf_map`.  "Const" because arithmetic on these pointers is forbidden.|
|PTR_TO_MAP_VALUE | Pointer to the **value stored in a map element**. |
|PTR_TO_MAP_VALUE_OR_NULL| Either a pointer to a map value, or NULL; map accesses (see section 'eBPF maps', below) return this type, which becomes a PTR_TO_MAP_VALUE when checked != NULL. Arithmetic on these pointers is forbidden. | 
| PTR_TO_STACK | Frame pointer|
| PTR_TO_PACKET | `skb->data`   |
|PTR_TO_PACKET_END | `skb->data + headlen`; arithmetic forbidden |
|PTR_TO_SOCKET| Pointer to `struct bpf_sock_ops`, implicitly refcounted |
|PTR_TO_SOCKET_OR_NULL| Either a pointer to a socket, or NULL; socket lookup returns this type, which becomes a PTR_TO_SOCKET when checked != NULL. PTR_TO_SOCKET is reference-counted, so programs must release the reference through the socket release function before the end of the program. Arithmetic on these pointers is forbidden. |

同时存在一个问题, 一个指针可能是以上某种结构体指针加上偏移计算得到的.
一种是加上固定偏移, 一种是加上可变偏移.

>  The former is used when an exactly-known value (e.g. an immediate
operand) is added to a pointer, while the latter is used for values which are
not exactly known.  The variable offset is also used in SCALAR_VALUEs, to track
the range of possible values in the register.
The verifier's knowledge about the variable offset consists of:
* minimum and maximum values as unsigned
* minimum and maximum values as signed
* knowledge of the values of individual bits, in the form of a 'tnum': a u64
'mask' and a u64 'value'.  1s in the mask represent bits whose value is unknown;
1s in the value represent bits known to be 1.  Bits known to be 0 have 0 in both
mask and value; no bit should ever be 1 in both.  For example, if a byte is read
into a register from memory, the register's top 56 bits are known zero, while
the low 8 are unknown - which is represented as the tnum (0x0; 0xff).  If we
then OR this with 0x40, we get (0x40; 0xbf), then if we add 1 we get (0x0;
0x1ff), because of potential carries.


## 直接的数据访问 Direct packet access


- 示例一
```
R3=pkt(id=0,off=0,r=14)
```

id=0 指没有额外的变量与该寄存器运算
off=0 指没有额外的常量与该寄存器运算
r=14 指的是合法的访问偏移,即 [R3, R3 + 14)


- 示例二
```
R5=pkt(id=0,off=14,r=14)
```
off=14 指该寄存器运算与一个常数进行运算
r5 += 14
通过R5可访问范围就是 [R5, R5 + 14 - 14), 即0字节.




- 示例三
直接访问 packet
```
R0=inv1 R1=ctx R3=pkt(id=0,off=0,r=14) R4=pkt_end R5=pkt(id=0,off=14,r=14) R10=fp
6:  r0 = *(u8 *)(r3 +7) /* load 7th byte from the packet */
7:  r4 = *(u8 *)(r3 +12)
8:  r4 *= 14
9:  r3 = *(u32 *)(r1 +76) /* load skb->data */
10:  r3 += r4


11:  r2 = r1
12:  r2 <<= 48
13:  r2 >>= 48
14:  r3 += r2


15:  r2 = r3
16:  r2 += 8
17:  r1 = *(u32 *)(r1 +80) /* load skb->data_end */
18:  if r2 > r1 goto pc+2
R0=inv(id=0,umax_value=255,var_off=(0x0; 0xff)) R1=pkt_end R2=pkt(id=2,off=8,r=8) R3=pkt(id=2,off=0,r=8) R4=inv(id=0,umax_value=3570,var_off=(0x0; 0xfffe)) R5=pkt(id=0,off=14,r=14) R10=fp
19:  r1 = *(u8 *)(r3 +4)
```

`packet registers` 只允许 `add`/`sub` 运算, 其它运算操作会导致寄存器状态变成标量值.
变成标量值就再也无法用于 packet access


`R3=pkt(id=2,off=0,r=8)` 中, id=2, 是因为存在 两条` r3 += rX`, 这个操作会导致超过或
小于 `skb->data` 的数据范围. 所以验证器理应避免这种情况.

第14条指令中, `r3 += r2` 中 r2 是一个超过16bit的值, 任何后续关于 `skb->data` 的检查都不会再提供有效的范围信息,因为没有用啊.
直接导致通过该指针访问数据的尝试都会得到 `so attempts to read
through the pointer will give "invalid access to packet" error` 错误.




[1]: https://www.kernel.org/doc/Documentation/networking/filter.txt

参考资料:

https://www.kernel.org/doc/Documentation/networking/filter.txt

include/uapi/linux/filter.h

include/uapi/linux/bpf.h

include/uapi/linux/bpf_common.h

https://github.com/iovisor/bpf-docs/blob/b5ac15bfefc25fb13b4178a3fed2932fc2a795f1/eBPF.md
