# skbtracer

skbtracer 基于 ebpf 技术的 skb 网络包路径追踪利器， 实现代码基于 [BCC](https://github.com/iovisor/bcc) (required Linux Kernel 4.15+)

## 使用样例

```
skbtracer.py                                      # trace all packets
skbtracer.py --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
skbtracer.py --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
skbtracer.py --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
skbtracer.py -t -T -p 1 --debug -P 80 -H 127.0.0.1 --proto=tcp --kernel-stack --icmpid=100 -N 10000
```

运行效果

```bash
$ sudo ./skbtracer.py -c 100
time       NETWORK_NS   CPU    INTERFACE          DEST_MAC     IP_LEN PKT_INFO                                 TRACE_INFO
[06:47:28 ][4026531992] 0      b'nil'             00042de08c77 196    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a594e0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            00042de08c77 196    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a594e0.0:b'ip_finish_output'
[06:47:28 ][4026531992] 0      b'eth0'            00042de08c77 196    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a594e0.0:b'__dev_queue_xmit'
[06:47:28 ][4026531992] 0      b'nil'             000439849c02 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ee0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            000439849c02 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ee0.0:b'ip_finish_output'
[06:47:28 ][4026531992] 0      b'eth0'            000439849c02 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ee0.0:b'__dev_queue_xmit'
[06:47:28 ][4026531992] 0      b'nil'             000429e08c77 228    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ae0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            000429e08c77 228    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ae0.0:b'ip_finish_output'
[06:47:28 ][4026531992] 0      b'eth0'            000429e08c77 228    T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ae0.0:b'__dev_queue_xmit'
[06:47:28 ][4026531992] 0      b'nil'             000439e08c77 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ce0.0:b'ip_output'
[06:47:28 ][4026531992] 0      b'eth0'            000439e08c77 76     T_ACK,PSH:172.17.0.14:22->101.87.140.43:18359 ffff8a7572a59ce0.0:b'ip_finish_output'
```

## 功能增强

1. 调整基于抓取数量的实现（更加精准，避免了部分环境下异常被忽略）
2. 增加了 ip 长度的字段
3. 增加了运行 cpu 的字段

本文代码来自于 [gist](https://gist.github.com/chendotjs/194768c411f15ecfec11e7235c435fa0
)

更通用的网络方案参见仓库 [WeaveWorks tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf)

## 相关文档

* [使用 ebpf 深入分析容器网络 dup 包问题](https://blog.csdn.net/alex_yangchuansheng/article/details/104058072)
* [使用 Linux tracepoint、perf 和 eBPF 跟踪数据包 (2017)](https://github.com/DavadDi/bpf_study/blob/master/trace-packet-with-tracepoint-perf-ebpf/index_zh.md)
