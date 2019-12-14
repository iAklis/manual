# 从网络延迟到 Cgroups 所导致的 slab 缓存堆积



在某次群友分享学习的时候了解到 Github 团队定位一个问题的过程。

一个HTTP服务在连接上观察到超过100ms的延迟。
在观测到服务超时的时刻，后端MySQL数据库的查询都在几毫秒内完成。
现象仅仅在客户端可以观测到。

最后到定位 cgroups 苟延残喘导致的缓存堆积问题, 其中用到的工具非常地香,解决问题的思路非常美妙.


## 问题解构

> 排除可能会影响判断的因素，因为多余的因素可能不直接导致问题，而是放大问题。

问题的讨论基础

1. 首先应用程序本身的性能是没有问题的,程序经过压测流量也远远未到峰值。
2. 其次机器本身的性能是没有问题，不会出现什么SSD突然放电之类的。

下面开始一行至少一个知识点。

从流量重现开始.

从集群外模拟服务的正常流量和查询对服务进行拔测，通过 tcpdump 发现延迟存在于 TCP 握手包之间，也就是（`SYN`和`SYN—ACK`)。

一步步缩小范围,排除业务流量的影响改用 hping3，单纯地定时定量模拟 TCP 握手过程，发现延迟依然存在。
K8s 的 NodePort 是由 iptabels NAT 实现的，把 `(Nodeip,Podport)` 的包转换成 `(PodIp, Podport)`. 所以把发起请求的来源从集群外转移动另一个Pod中，通过 Pod 之间的 Overlay 网络发包，排除 `kube-proxy` 及其数百条 iptables 规则的影响，但发现延迟依然于 TCP handshake 之间存在。

又一方面考虑到会不会是已经存在的 iptables conntrack 有关的规则影响到了 TCP 的握手过程，于是 hping3 的 syn ping 模式直接模拟 icmp ping 操作，发现问题依然存在，但几乎排除了iptables在这问题里面所有的影响，问题范围缩小了。

Overlay 网络是由 `IPIP` 模式实现的，从字面上理解 IPIP 就是把一个IP层的包套在另一个IP包里，即通过 IP层封装IP层的一个 tunnel。 这种模式下宿主机都会有一个 tun 设备，通过它实现了两个 Node 之间的互联互通。排除 IPIP 影响，直接测试 集群内外的Node 到 服务所在Node 之前的通信，发现问题和业务无关，只跟业务所在的机器有关。
至此，问题的描述就变成了是服务所在的这个机器会让回包延迟增大。


### 换个角度

通过对比 TCP 和 ICMP 结果的接收方的数据包的排序(基于序列号)之间的差异.
ICMP 数据包始终以与发送时相同的顺序达到,但是时间不均匀.
TCP 数据包有时会交错到达,但其中一部分会停顿.

还有值得注意的地方是,如果对 syn 数据包的端口进行计数,则这些端口在接收方的顺序不正确,而在发送方的顺序是正常的.

就像我们在数据中心中一样，现代服务器NIC处理包含TCP与ICMP的数据包之间存在细微的差异。

当数据包到达时，NIC会"按连接"对数据包进行哈希处理，并尝试在接收队列之间划分连接，每个队列（大约）委派给给定的CPU内核。对于 TCP，此哈希同时包括源IP和目标IP以及端口。换句话说，每个连接的`散列`（可能）都不同。对于ICMP，由于没有端口，因此仅对 `IP源` 和`目标`进行哈希处理。

另一个新的观察结果是，我们可以从ICMP vs TCP中的序列号看出，ICMP在此期间观察到了两台主机之间所有通信的停顿，而 TCP 没有。这告诉我们，`RX队列(receive)`很可能有问题，几乎可以肯定地表明，停顿是在处理RX数据包中，而不是在发送响应中。


至此, 我们知道它在处理数据包方面有所问题, 并且在某些 Kube-node 上位于接收端. 
Kubenetes 的网络问题的嫌疑被排除了.


### Linux 的包处理

Linux内核处理数据包的方式，最传统的实现就是网卡接收到一个数据包，并向Linux内核发送一个中断，指出存在应该处理的数据包。 内核停止其他工作，将上下文切换到中断处理程序，处理数据包，然后切换回其正在执行的操作。

所有的 I/O 中断处理程序都执行四个相同的基本操作:

1. 在内核态堆栈中保存 IRQ 的值 和寄存器的内容.
2. 为正在给IRQ线服务的PIC发送一个应答,这将允许PIC进一步发出中断.
3. 执行共享这个IRQ的所有设备的中断服务例程(ISR)
4．跳到 ret\_from\_intr() 的地址后终止.


这种上下文切换很慢，在90年代对10Mbit NIC来说可能还不错，但是在NIC为10G并且以最大线路速率运行的现代服务器上，每秒可以带来大约1500万个数据包，而在具有八核的小型服务器上 这可能意味着内核每个内核每秒中断数百万次。

多年前，Linux不再不断处理中断，而是添加了NAPI，这是现代驱动程序用来提高高数据包速率的网络API。 在低速率下，内核仍然按照我们提到的方法接受来自NIC的`中断`。 一旦有足够的数据包到达并超过阈值，它将禁用中断，而是开始轮询NIC并分批提取数据包。 该处理在“ softirq”或软件中断上下文中完成。 这发生在系统调用和硬件中断的末尾，这是 _内核（而不是用户空间）_ 已经在运行的时候。


这使得系统"快"得多，但是带来了另一个问题。 如果要处理的数据包如此之多，以至于我们花了所有的时间来处理来自NIC的数据包，但又没有时间让用户空间进程实际上耗尽那些队列（从TCP连接等读取），会发生什么？ 最终，队列将满，我们将开始丢弃数据包。 

为了使公平起见，内核将在给定softirq上下文中处理的数据包数量/时间作限制。

软中断函数可以重新激活自己; 实际上, 网络软中断和 tasklet 软中断都可以这么做.
此外, 像网卡上数据包泛滥这样的外部事件可能以高频率激活软中断, 这会导致性能问题.

由此产生了两种策略:

1. 忽略do\_softirq() 运行时新出现的软中断.对网络开发者来说,软中断的等待时间是不可接受的.

2. 第二种策略在于不断地重新检查挂起的软中断.如果网卡接收高频率的数据包流,或者如果一个软中断函数总是激活自己,那么,do\_softirq()函数就会永不返回,用户态程序实现上就会停止执行.

如果已经执行的软中断又被激活, do\_softirq() 则唤醒内核线程并终止 (\_\_do\_softirq()的第10步). 内核线程有较低的优先级,因此用户程序就会有机会运行;同时,如果机器空闲,挂起的软中断就会很快被执行.

只要有待处理的软中断,由 softirq\_pending() 函数负责发现.
Ksoftirq(您将在每个内核的ps中看到其中一个) 就会调用 do\_softirq 去处理它们.

ksoftirqd 内核线程本质上就是这么一段代码

```
for (;;) {
    set_current_state(TASK_INTERRUPTIBLE);
    schedule();
    
    /* now in TASK_RUNNING state */
    while (local_softirq_pending()) {
        preempt_disable();
        do_softirq();
        preempt_enable();
        cond_resched();
    }
}
```


通过循环不断地执行这样的操作,重新解发的软中断也会被执行.发果有必要,每次迭代之后都会调用 schedule() 以使让更重要的进程得到处理机会.
当所有需要执行的操作都完成之后,该内核线程将自己设置为 TASK\_INTERRUPTIBLE 状态,唤起调度程序选择其他可执行进程投入运行.


```
  -------------      ------------------      ------------------
  | ksoftirqd |      | User's process |      |   Softirqs     |
  -------------      ------------------      ------------------
   Not scheduled          Running
                             |
                             o------------------------o
                                                      |
                                                __do_softirq()
                                                      |
                                              2ms & softirq pending?
                                              Schedule ksoftirqd
                                                      |
    Scheduled                o------------------------o
                             |
        o--------------------o
        |
     Running             Scheduled
        |
        o--------------------o
                             |
   Not scheduled          Running





Pending softirqs
                | | | |           | | | |       |
                v v v v           | | | |       v
   Processing   o-----o           | | | |       o--o
    softirqs    |     |           | | | |       |  |
                |     |           | | | |       |  |
                |     |           | | | |       |  |
   Userspace  o-o     o=========o | | | |  o----o  o---------o
                <-st->         | | | | |  |
                                | v v v v  |
   Ksoftirqd                    o----------o


```

如果两次 softirq 处理调用之间的时间增加，则在处理数据包之前，数据包可能会在NIC RX队列中停留一段时间。 

SYSCALL,比如 `read()` 这可能是导致CPU内核死锁的原因，也可能是导致内核无法运行softirqs的缓慢原因。


## 再进一步

上面得到了一个可能导致CPU内核死锁的原因,也不一定是死锁,但导致内核无法运行softirqs快速处理包的原因.

接下来就是设计步骤来进一步缩小范围.

如前所述，这些ICMP数据包被散列到单个NIC RX队列，并由单个CPU内核进行处理。 如果我们想了解内核在做什么，那么了解它们在何处（cpu内核）以及如何（softirq，ksoftirqd）处理这些数据包将很有帮助，以便我们及时采取行动。

从 ICMP 入手, 我们知道内核处理 icmp ping 数据包是通过内核函数 icmp\_echo
这个函数接收传入的 ICMP request并发送 ICMP reply.

https://gist.github.com/iAklis/bb2338a3ddd50712d23dc6f4409f7946


这是一段 bcc 脚本，可以通过对内核函数 `icmp_echo` 执行前下断，跳转执行给定的 eBPF 程序，Github 团队提供的脚本是有问题的，我稍作修改。通过传入的 `struct sk_buff *skb` 能够得到内核函数执行时候的上下文数据，我们现在可以将hping3观察到的高延迟数据包与处理它的进程相关联。 在具有某些上下文的情况下针对icmp\_seq值进行的捕获上的简单 grep 显示了在处理这些数据包之前发生的情况. 然后把它们作一个关联,筛选出RTT比较大的情况. 在 cadvisor的syscall softirq上下文中处理了一些数据包，处理不过来然后ksoftirqd接管并处理了积压，并且我们在相对应的seq关联上了在tcpdump中观察到的延迟包。


于是乎使用 perf record 打印对应CPU的核心当时的调用栈, 使用 strace 定位阻塞的系统系统。
最终定位到是read系统调用和mem\_cgroup\_\* 内核函数的问题。


`cat /sys/fs/cgroup/memory/memory.stat`

等价到 cadvisor 读到关于容器信息的 memory.stat 文件会耗费大量的时间。

这个问题不是 cadvisor 的问题，这个问题关系到本文的主旨。


## root cause


这个问题从整体上看, 是 memory cgroup 正在计算一个 namespace(container) 的内存使用情况.


当一个`namespace`内的所有进程都退出后, 这个`memory cgroups`也会被 docker 释放.
但是, 这个内存并不仅仅是进程的内存,进程的内存本身已经被回收了,但实际上,内核还给memory cgroups分配了缓存(kmem\_alloc), 用于 `dentries` 和 `inodes`.

这种现象称之为, `僵尸 cgroups (zombie cgroups)`.没有进程存在并且已经被删除但仍然占有内核上的内存. (有可能是 dentry 缓存,有可能是 page cache)


内核比起在每个cgroups释放的时候清理每个page中的缓存,选择了 去等待 这些页面缓存(这里被slabtop统计成reclaimed,free命令中的available) 在内核需要更多需要内存的时候 才去回收. 因为前者会非常慢,后者像是一种lazy way. 

在没有被完全回收掉 kmem 的内存的时候,这个cgroups其实还是一个幽灵.这并不是"泄漏",这并不是"泄漏",这并不是"泄漏".

因为这些内存并不是被某个进程占据不能被系统回收,说了能被系统回收开垦的内存,能叫泄漏吗.
当内核回收缓存中的最后一块内存时, cgroups才算完全被清理. 

讲道理是没有什么问题的.但是随着容器化,微服务化特别是K8s非常熟练地在机器之前迁移Pod,即在频繁执行容器创建和删除操作的主机上，删除 cgroup 之后仍保留特定的slab cache. 

cadvisor 只是受害者. 

slab 积累到一定程序的时候,系统会去回收它,回收这个过程系统不会响应用户程序.
所以在用户态的程序看来,内核僵死了从数十毫秒到数十秒的可能.

此时此刻对于延迟敏感的服务,表现就是超时. 对于开启了`kernel.hung_task_panic`在hang住的时候可能就直接 panic 了.

对于文件系统来说,大量的 dentry 的回收,可能让系统一直拿着 vfs 的锁.

峰回路转,知识串烧.


提供一个

Proof of concept:

```bash
#!/bin/bash

old_memcg_num=$(cat /proc/cgroups | awk '/memory/ {print $3}')

free -m
slabtop -o | head
echo "now the number of memory cgroup is                $old_memcg_num"
echo "begin to create cgroups"

prefix=/sys/fs/cgroup/memory/aklis

for i in {1..1000};
do
  mkdir $prefix-$i;
  bash -c "echo \$\$ > $prefix-$i/tasks; mkdir /tmp/$i; echo 'fubao'>/tmp/$i/pandada8;"
done

created_memcg_num=$(cat /proc/cgroups | awk '/memory/ {print $3}')
free -m
slabtop -o | head

echo "now the number of memory cgroup is                $created_memcg_num"
echo "begin to del cgroups that created by Poc, pddka!"

for i in {1..1000};
do
  rmdir $prefix-$i;
done

free -m
slabtop -o | head
deleted_memcg_num=$(cat /proc/cgroups | awk '/memory/ {print $3}')
echo "now the number of memory cgroup is                $deleted_memcg_num"

echo "P.S. remember to clear the tmp file (/tmp)"
```


参考资料:

https://github.blog/2019-11-21-debugging-network-stalls-on-kubernetes/

https://github.com/google/cadvisor/issues/1774

\<深入理解Linux内核\>