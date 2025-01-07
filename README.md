# Bullshark Fallback
[![rustc](https://img.shields.io/badge/rustc-1.51+-blue?style=flat-square&logo=rust)](https://www.rust-lang.org)
[![license](https://img.shields.io/badge/license-Apache-blue.svg?style=flat-square)](LICENSE)

This repo provides an experimental implementation of the asynchronous fallback protocol of [Bullshark](https://arxiv.org/pdf/2201.05677.pdf). The code is however incomplete and there are currently no plans to maintain it.



## Major changes
1. Client is no longer closed loop; instead, the worker will now inform the client if a batch is full and which transactions are cut off. Afterwhich, the client would have to resubmit the transactions to the new batch. 
## License
This software is licensed as [Apache 2.0](LICENSE).



## Dones
1. Each primary is now allocated an ID and is aware of this. 


## Todo's (Tentative and subject to progress)
1. Modify the header sending information to include a shard number that is contingent on:
```
primary_id

(virtual) dag
```