# Bullshark Fallback
[![rustc](https://img.shields.io/badge/rustc-1.51+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

This repo provides an experimental implementation of the asynchronous fallback protocol of [Bullshark](https://arxiv.org/pdf/2201.05677.pdf). The code is however incomplete and there are currently no plans to maintain it.



## Major changes
1. Client is no longer closed loop; instead, the worker will now inform the client if a batch is full and which transactions are cut off. Afterwhich, the client would have to resubmit the transactions to the new batch. 
## License
This software is licensed as [Apache 2.0](LICENSE).

## Some notes:
1. Main calculations of latencies are done via the committed and created messages in consensus/core and primary/proposer respectively.

## Dones
1. Each primary is now allocated an ID and is aware of this. 
2. headers now include shard information; this info also rotates per round in a determinsitic manner. 


## Todo's (Tentative and subject to progress)
1. modify consensus/src/dolphin to have early commit logic. 