# skbtracer

skbtracer on  ebpf (required Linux Kernel 4.15+)

原有功能增强
1. 调整基于抓取数量的实现（更加精准，避免了部分环境下异常被忽略）
2. 增加了 ip 长度的字段
3. 增加了运行 cpu 的字段

本文代码来自于 [gist](https://gist.github.com/chendotjs/194768c411f15ecfec11e7235c435fa0
)

相关文档参见这里 
* [使用 ebpf 深入分析容器网络 dup 包问题](https://blog.csdn.net/alex_yangchuansheng/article/details/104058072)
* [使用 Linux tracepoint、perf 和 eBPF 跟踪数据包 (2017)](https://github.com/DavadDi/bpf_study/blob/master/trace-packet-with-tracepoint-perf-ebpf/index_zh.md)
