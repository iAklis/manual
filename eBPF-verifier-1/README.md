# verifier 战争其一

A story about fighting against bpf verifier

@iAklis (aka. Aklis Chen)

本篇作为 [https://github.com/iAklis/manual/tree/master/eBPF](https://github.com/iAklis/manual/tree/master/eBPF) 的补充理解。

我们用一个简单的例子来展示验证器的存在，例子的实际意义是数据脱敏打码前置处理，本质上是在BPF执行的上下文中作数据修改。

### 栈上功夫：

```c
# Code 1
int res;
char fname[PATH_MAX];
char fmt[] = "create file name %s \n";
res = bpf_probe_read_kernel_str(&fname, sizeof(dentry->d_iname), dentry->d_iname);
if (res > 5) {
	fname[res-2] = '*';
	fname[res-3] = '*';
	fname[res-4] = '*';
}

bpf_trace_printk(fmt, sizeof(fmt), fname);
```

编译通过没有问题，但当我们准备把这一段代码加载进内核的时候，就会触发 `verifiler`.

于是我们会被糊一脸。

```c
# Code 2
26: (bf) r1 = r10
; 
27: (07) r1 += -104
; res = bpf_probe_read_kernel_str(&fname, sizeof(dentry->d_iname), dentry->d_iname);
28: (b7) r2 = 32
29: (bf) r3 = r8
30: (85) call bpf_probe_read_kernel_str#115
last_idx 30 first_idx 0
regs=4 stack=0 before 29: (bf) r3 = r8
regs=4 stack=0 before 28: (b7) r2 = 32
31: (67) r0 <<= 32
32: (c7) r0 s>>= 32
33: (b7) r1 = 6
; if (res > 5) {
34: (6d) if r1 s> r0 goto pc+7
 R0_w=inv(id=0,umin_value=6,umax_value=2147483647,var_off=(0x0; 0x7fffffff)) R1_w=inv6 R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmmmmmm fp-88=mmmmmmmm fp-96=mmmmmmmm fp-104=mmmmmmmm fp-112=??mmmmmm fp-120=inv7308604895909997673 fp-128=inv7358993341648040547
35: (bf) r1 = r10
; fname[res-2] = '*';
36: (07) r1 += -104
37: (0f) r0 += r1
last_idx 37 first_idx 31
regs=1 stack=0 before 36: (07) r1 += -104
regs=1 stack=0 before 35: (bf) r1 = r10
regs=1 stack=0 before 34: (6d) if r1 s> r0 goto pc+7
regs=1 stack=0 before 33: (b7) r1 = 6
regs=1 stack=0 before 32: (c7) r0 s>>= 32
regs=1 stack=0 before 31: (67) r0 <<= 32
 R0_rw=invP(id=0) R6_w=ctx(id=0,off=0,imm=0) R7_w=inv(id=0) R8_w=inv(id=0) R10=fp0 fp-8_w=mmmmmmmm fp-16_w=00000000 fp-24_w=00000000 fp-32_w=00000000 fp-40_w=00000000 fp-48_w=00000000 fp-56_w=00000000 fp-64_w=00000000 fp-72_w=00000000 fp-80=mmmmmmmm fp-88=mmmmmmmm fp-96=mmmmmmmm fp-104=mmmmmmmm fp-112=??mmmmmm fp-120_w=inv7308604895909997673 fp-128_w=inv7358993341648040547
parent didn't have regs=1 stack=0 marks
last_idx 30 first_idx 0
regs=1 stack=0 before 30: (85) call bpf_probe_read_kernel_str#115
38: (b7) r1 = 42
; fname[res-3] = '*';
39: (73) *(u8 *)(r0 -3) = r1
variable stack access var_off=(0x0; 0x7fffffff) off=-107 size=1
processed 38 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
```

- `Instruction 26-27/35-36`  r10 当作 rbp 帧指针。 r10 - 104 是指从栈底到 -104 的地方，在这里就是 fname 指向的地址。
- `Instruction 39` 指令中 `variable stack access` 表示原本指向栈的指针 r10 与常数偏移 -107 *-104  + (-3)* 之后，再加上了一个变量偏移。这个时候 verifier 是比较懒地去复用上面的有效范围，也不是重新判断寻址范围是否在总的堆栈范围之内。而是因为不确定性就拒绝加载，有点过于严格反而影响了体验。希望也应该是 verifier 未来会改进的一个点。

`Rx_w` 之类的值是 bpf verifier 额外输出的上下文调试信息。

`inv` 值，在下面 verifier 输出的错误。这里我们理解成不可信，反正就是 not safe 的意思

用点 trick 把 res的最大值范围拉到 1。

```c
# Code 3
res = bpf_probe_read_kernel_str(&fname, sizeof(dentry->d_iname), dentry->d_iname);
	if (res > 0) {
		fname[res&0x1] = '\0';
} // 这里的例子没有实际意义
```

这种就是 verifier 能做好但还没做好的地方。

```c
# Code 4
; fname[res&0x1] = '\0';
39: (73) *(u8 *)(r1 +0) = r6
variable stack access var_off=(0x0; 0x1) off=-104 size=1
processed 38 insns (limit 1000000) max_states_per_insn 0 total_states 1 peak_states 1 mark_read 1
```

*PTR_TO_STACK* + off + var_off  必然在有效范围内，但如上文所说，并非重新判断有效范围而是直接拒绝。

所以目前 verifier 只接受 ***PTR_TO_STACK + offset*** 是一个运行前可确定的值，拒绝可变值。

### eBPF 的妖精乡

基于以上限制，实现这个倒数几位打码需求的代码就会变得扭曲起来。实际上单单 BPF vm 本身并不能发挥它本来的 super power, 需要他的好帮手 BPF Map.

一方面它也是预分配空间，可以在代码运行前划定有效的安全范围。另一方它没有 BPF STACK上那近乎苛刻的条件，可以使用变量偏移。

第一处扭曲的地方，把栈上操作去掉，我们简单得到以下代码：

```c
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, PATH_MAX);
    __uint(max_entries, 1);
} tmp_path_map SEC(".maps");
...
int res;
char * fname = bpf_map_lookup_elem(&tmp_path_map, &index);
if (!fname)
      return 0;
char fmt[] = "create file name %s \n";
res = bpf_probe_read_kernel_str(fname, sizeof(dentry->d_iname), dentry->d_iname);
if (res > 5) {
	fname[res-2] = '*';
	fname[res-3] = '*';
	fname[res-4] = '*';
}

bpf_trace_printk(fmt, sizeof(fmt), fname);
```

在 ebpf 会触发 verifier 边界警告，拒绝加载。

```c
; res = bpf_probe_read_kernel_str(fname, sizeof(dentry->d_iname), dentry->d_iname);
34: (bf) r1 = r8
35: (b7) r2 = 32
36: (bf) r3 = r9
37: (85) call bpf_probe_read_kernel_str#115
 R0=map_value(id=0,off=0,ks=4,vs=32,imm=0) R1_w=map_value(id=0,off=0,ks=4,vs=32,imm=0) R2_w=inv32 R3_w=inv(id=0) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8_w=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9_w=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96_w=inv7308604895909997673 fp-104_w=inv7358993341648040547
last_idx 37 first_idx 20
regs=4 stack=0 before 36: (bf) r3 = r9
regs=4 stack=0 before 35: (b7) r2 = 32
38: (67) r0 <<= 32
39: (c7) r0 s>>= 32
40: (b7) r1 = 6
; if (res > 5) {
41: (6d) if r1 s> r0 goto pc+5
 R0_w=inv(id=0,umin_value=6,umax_value=2147483647,var_off=(0x0; 0x7fffffff)) R1_w=inv6 R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96=inv7308604895909997673 fp-104=inv7358993341648040547
; fname[res-2] = '*';
42: (0f) r0 += r8
last_idx 42 first_idx 38
regs=1 stack=0 before 41: (6d) if r1 s> r0 goto pc+5
regs=1 stack=0 before 40: (b7) r1 = 6
regs=1 stack=0 before 39: (c7) r0 s>>= 32
regs=1 stack=0 before 38: (67) r0 <<= 32
 R0_rw=invP(id=0) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8_rw=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9_w=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96_w=inv7308604895909997673 fp-104_w=inv7358993341648040547
parent didn't have regs=1 stack=0 marks
last_idx 37 first_idx 20
regs=1 stack=0 before 37: (85) call bpf_probe_read_kernel_str#115
43: (b7) r1 = 42
; fname[res-3] = '*';
44: (73) *(u8 *)(r0 -3) = r1
 R0_w=map_value(id=0,off=0,ks=4,vs=32,umin_value=6,umax_value=2147483647,var_off=(0x0; 0x7fffffff)) R1_w=inv42 R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96=inv7308604895909997673 fp-104=inv7358993341648040547
R0 unbounded memory access, make sure to bounds check any array access into a map
processed 42 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 1
```

- `Instruction 38/39` 这种左右摇摆的是因为 r0 的返回类型是 int 只取低 32 位。
- `Instruction 41` 显式判断得到了 r0 的下边界。r0 是调用 func  **`bpf_probe_read_str`** 之后保存其返回值的寄存器。verifier prune 之后得到的 r0 接下来取值范围是`[6, 2147483647)` 。
- `Instruction 42` 在此上下文中， R8 保存的是 fname 指向的地址，**R0 + R8** 就是 &fname[res], 呼应 **Instruction 44** 中的 **r0**-3,既 **R0+R8**-3 , 就是 &fname[res-3]。
- `Instruction 44` 在这里是对 map 上的内存的访问，R0 既 map_value fname.  显式 explicit 地为字符串数组写入`'\*'`。

上面的错误信息总结一下就是因为我们只通过对 `res` 进行下边界`if (res >5)`的判断，进入到修改字符串数据的作用域时我们可以确定 res 的取值范围是 `[6,` ，这是通过 verifier 的静态分析手段确定的。 但是由于我们没有进行上边界的检查，verifier 无法确定，所以抛出了错误。

verifier 不知道，就无法确定边界，无法确定边界，就是不安全。

所以我们对它显示指定范围，划清界限。

代码进一步扭曲了起来。来来来你缺上边界是吧，补上补上。

```c
int res;
char * fname = bpf_map_lookup_elem(&tmp_path_map, &index);
if (!fname)
      return 0;
char fmt[] = "create file name %s \n";
res = bpf_probe_read_kernel_str(fname, sizeof(dentry->d_iname), dentry->d_iname);
if ((res > 5) && (res < PATH_MAX)) {
    fname[res-2] = '*';
    fname[res-3] = '*';
    fname[res-4] = '*';
}

bpf_trace_printk(fmt, sizeof(fmt), fname);
```

然后我们又被 verifier 糊一脸？？？

```c
37: (85) call bpf_probe_read_kernel_str#115
 R0=map_value(id=0,off=0,ks=4,vs=32,imm=0) R1_w=map_value(id=0,off=0,ks=4,vs=32,imm=0) R2_w=inv32 R3_w=inv(id=0) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8_w=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9_w=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96_w=inv7308604895909997673 fp-104_w=inv7358993341648040547
last_idx 37 first_idx 20
regs=4 stack=0 before 36: (bf) r3 = r9
regs=4 stack=0 before 35: (b7) r2 = 32
; if ((res > 5) && (res < PATH_MAX)) {
38: (bf) r1 = r0
39: (07) r1 += -6
40: (67) r1 <<= 32
41: (77) r1 >>= 32
42: (25) if r1 > 0x19 goto pc+7
 R0=inv(id=0) R1_w=inv(id=0,umax_value=25,var_off=(0x0; 0x1f)) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96=inv7308604895909997673 fp-104=inv7358993341648040547
; fname[res-2] = '*';
43: (67) r0 <<= 32
44: (c7) r0 s>>= 32
; fname[res-2] = '*';
45: (0f) r0 += r8
last_idx 45 first_idx 38
regs=1 stack=0 before 44: (c7) r0 s>>= 32
regs=1 stack=0 before 43: (67) r0 <<= 32
regs=1 stack=0 before 42: (25) if r1 > 0x19 goto pc+7
regs=1 stack=0 before 41: (77) r1 >>= 32
regs=1 stack=0 before 40: (67) r1 <<= 32
regs=1 stack=0 before 39: (07) r1 += -6
regs=1 stack=0 before 38: (bf) r1 = r0
 R0_rw=invP(id=0) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8_rw=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9_w=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96_w=inv7308604895909997673 fp-104_w=inv7358993341648040547
parent didn't have regs=1 stack=0 marks
last_idx 37 first_idx 20
regs=1 stack=0 before 37: (85) call bpf_probe_read_kernel_str#115
value -2147483648 makes map_value pointer be out of bounds
processed 43 insns (limit 1000000) max_states_per_insn 0 total_states 2 peak_states 2 mark_read 1
```

- `Instruction 42` 显示出现其为诡异的问题，明明是显示判断了最大值和最小值的范围，为什么在bpf code 里面只编译成 **if r1 > 0x19 goto pc+7** ，这大概是 LLVM 本身的某种问题。verifier 得到R1 的一个魔幻的范围 小于 25

LLVM？ 我躲开我躲开。

按预期我们应该得到

```c
	
27:       67 00 00 00 20 00 00 00 r0 <<= 32
28:       c7 00 00 00 20 00 00 00 r0 s>>= 32
29:       b7 01 00 00 06 00 00 00 r1 = 6
30:       6d 01 06 00 00 00 00 00 if r1 s> r0 goto +6 <LBB2_4>
31:       65 00 0a 00 1f 00 00 00 if r0 s> 31 goto +10 <LBB2_5>
32:       0f 60 00 00 00 00 00 00 r0 += r6
33:       b7 01 00 00 2a 00 00 00 r1 = 42
34:       73 10 fd ff 00 00 00 00 *(u8 *)(r0 - 3) = r1
35:       73 10 fe ff 00 00 00 00 *(u8 *)(r0 - 2) = r1
36:       73 10 fc ff 00 00 00 00 *(u8 *)(r0 - 4) = r1
```

实际我们得到

```c
38: (bf) r1 = r0
39: (07) r1 += -6
40: (67) r1 <<= 32
41: (77) r1 >>= 32
42: (25) if r1 > 0x19 goto pc+7
 R0=inv(id=0) R1_w=inv(id=0,umax_value=25,var_off=(0x0; 0x1f)) R6=ctx(id=0,off=0,imm=0) R7=inv(id=0) R8=map_value(id=0,off=0,ks=4,vs=32,imm=0) R9=inv(id=0) R10=fp0 fp-8=mmmmmmmm fp-16=00000000 fp-24=00000000 fp-32=00000000 fp-40=00000000 fp-48=00000000 fp-56=00000000 fp-64=00000000 fp-72=00000000 fp-80=mmmm???? fp-88=??mmmmmm fp-96=inv7308604895909997673 fp-104=inv7358993341648040547
; fname[res-2] = '*';
```

 对 R1 进行的边界判断一方面丢失了下边界的结果，另一方面判断边界没有反馈回 R0 。

而接下来的代码

```c
43: (67) r0 <<= 32
44: (c7) r0 s>>= 32
; fname[res-2] = '*';
45: (0f) r0 += r8
```

用的是 r0 与 r8 , r8 保存 fname 指向的地址，即 fname[r0] ，提前被verifier 截胡。

**value -2147483648 makes map_value pointer be out of bounds** 

可是为什么合并只剩下一条呢？

LLVM 的优化使得它会把 (r0 > 5) 与 (r0 < PATH_MAX) 合并成 (6,24]，这个开关还不知道怎么开关。

### 还可以再扭曲一点。

```c
int res;
char * fname = bpf_map_lookup_elem(&tmp_path_map, &index);
if (!fname)
    return 0;
char fmt[] = "create file name %s \n";
res = bpf_probe_read_kernel_str(fname, sizeof(dentry->d_iname), dentry->d_iname);
if ((res > 5)) {
    fname[res-2 & 0x1F] = '*';
    fname[res-3 & 0x1F] = '*';
    fname[res-4 & 0x1F] = '*';
}

bpf_trace_printk(fmt, sizeof(fmt), fname);
```

这样做的算术意义是让 res-x 的结果 ≤ 31 即 0x1f。完全意义上了为了通过 verifier 的验证。

既然 verifier 能够通过对一个 64bit 的寄存器进行左右摇摆。

```c
38: (67) r0 <<= 32
39: (c7) r0 s>>= 32
```

 来判断它的的取值范围是一个 [-2^31, 2^31) 的范围，那么自然这种 trick 也能被我们用上。

 

## PTR_TO_CTX

随便拿一个上次文章里的代码示例，因为它刚好是一个操作 CTX 的例子。

```c
SEC("HostIngress")
int handle_hingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	struct eth_hdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);
	struct udphdr *udp = data + sizeof(*eth) + sizeof(*iph);
	void *data_end = (void *)(long)skb->data_end;
	char fmt[] = "tigger at HostIngress len %d %u \n";
	void *offset = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udp);
	/* single length check */
	if (offset > data_end)
		return 0;

	bpf_trace_printk(fmt, sizeof(fmt), data_end - offset, ***(uint*)(offset + 1)**);
	return TC_ACT_OK;
}
```

加载它，塞满它。

```bash
tc qdisc del dev docker0 clsact
tc qdisc add dev docker0 clsact
tc filter show dev docker0 ingress
tc filter add dev docker0 ingress bpf da obj vethtcxgress.o sec HostIngress verbose
```

verifier 验证边界

```c
Verifier analysis:

0: (61) r3 = *(u32 *)(r1 +80)
1: (61) r1 = *(u32 *)(r1 +76)
2: (b7) r2 = 10
3: (6b) *(u16 *)(r10 -16) = r2
4: (18) r2 = 0x207525206425206e
6: (7b) *(u64 *)(r10 -24) = r2
7: (18) r2 = 0x656c207373657267
9: (7b) *(u64 *)(r10 -32) = r2
10: (18) r2 = 0x6e4974736f482074
12: (7b) *(u64 *)(r10 -40) = r2
13: (18) r2 = 0x6120726567676974
15: (7b) *(u64 *)(r10 -48) = r2
16: (bf) r2 = r1
17: (07) r2 += 42
18: (2d) if r2 > r3 goto pc+6
 R1_w=pkt(id=0,off=0,r=42,imm=0) R2_w=pkt(id=0,off=42,r=42,imm=0)
 R3_w=pkt_end(id=0,off=0,imm=0) R10=fp0 fp-16=??????mm fp-24_w=inv2338816402538176622 fp-32_w=inv7308251975544828519 fp-40_w=inv7947011056609009780 fp-48_w=inv6998719600785844596
19: (1f) r3 -= r2
20: (61) r4 = *(u32 *)(r1 +43)
invalid access to packet, off=43 size=4, R1(id=0,off=0,r=42)
R1 offset is outside of the packet
processed 17 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0
```

其中 `sizeof(*eth) + sizeof(*iph) + sizeof(*udp)` 的值是 42.

- `Instruction 17`  对 offset 显示赋值，它是一个指针，偏移处是 UDP 包 data 开始处。 offset = data + 42。
- `Instruction 18`  进行**显式的边界检查**（bound check）如果超过边界（r3，即 data_end)，就执行 goto, 避免访问。
- `Instruction 20`  访问指针所指向的地址。**寻址访问** 当然是通过 `*` 访问一个指针。这是 r1 是一个指向 **`包`** 的指针，所以在这里（指当前上下文 tc filter bpf prog中）它属于一个 PTR_TO_CTX ，通过 `is_valid_access`验证。 [https://github.com/iAklis/manual/tree/master/eBPF#对-ctx-的访问限制](https://github.com/iAklis/manual/tree/master/eBPF#%E5%AF%B9-ctx-%E7%9A%84%E8%AE%BF%E9%97%AE%E9%99%90%E5%88%B6)

对比 `Instruction 19` ，也能直接地感受到 `*` 寻址操作才会触发验证器的检查。

```
R1_w=pkt(id=0,off=0,r=42,imm=0)
```

`id=0`指没有额外的变量与该寄存器运算，`off=0` 指没有额外的常量与该寄存器运算，`r=42` 指的是合法的访问偏移,即 `[R1, R1 + 42)`。

根据 umax_value + (int)off + (int)size， r1 + 43 + 4 超过了 `[R1, R1 + 42)`

`43` 是实际访问偏移，`4` 是访问目标 size。

接下来要把 R1 指向的 CTX 的合法偏移范围声明为新的范围。 47 - 42 = 5

**Instruction 18  应该使得 R1_w=pkt(id=0,off=0,r=47,...)**

所以更新

```diff
< 	if (offset > data_end)
---
> 	if (offset + 5 > data_end)
```

## invalid mem access

这个应该是一开始最容易遇到的问题，通常是改 bcc 的例子然后自己跑不起来的。

为什么会放到这么后面是因为首先理解了前面两种类型的 direct memory access，剩下的没有 BPF 可以直接访存的内存。

必须通过 bpf_probe_read_XXXX 系统的 helper 来帮你读取想要的内存。

当出现这个小标题的错误的时候，检查两点就好。

1. 直接访问了取自 ctx  的指针。
2. 直接访问了 prealloc 之外的内存（偏移偏到东南亚去了）。在这里我把 STACK 和 BPF MAP 类型的内存都当做是 PREALLOC，因为确实如此。

在我意识到妨碍我搞事的不止 verifier 之后，有些命题是否成立还待考虑。


## References

[https://github.com/iAklis/manual/tree/master/eBPF](https://github.com/iAklis/manual/tree/master/eBPF)

[https://www.kernel.org/doc/Documentation/networking/filter.txt](https://www.kernel.org/doc/Documentation/networking/filter.txt)