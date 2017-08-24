# LEARNING PWN DAY BY DAY
*author:pUck*
## Overview
***
**PWN入门题库**, 因为学习系统安全的需要，暑假伊始从零学习PWN，CTF赛题有多种多样的类型，由于小白如作者学习能力捉鸡并且两个月来琐事不断，也仅仅学会了PWN的皮毛，然而从第一次xman选拔赛遇到基础题手忙脚乱到最后线下赛（onsite）拿到一血，也算小有进步吧。网上pwn入门教程繁多，却没有系统的题库。乘记忆还没有模糊，分享一些适宜从零开始步步学习的题目。`目录`的名称即学习时候需要掌握的基本技术的``术语``，通过度娘或者谷哥你可以看到详细的介绍。
***

### DIR
```
.
├── heap
│   ├── force_of_house
│   ├── force_of_spirit
│   ├── heap_mix
│   │   ├── note1
│   │   ├── note2
│   │   └── note3
│   └── unlink
│       ├── unlink1
│       └── unlink2
└── stack
    ├── fmt #格式化字符串漏洞利用
    │   ├── ebp
    │   └── normal
    │       └── fmt_string_write_got
    ├── ret2dlreslove #当没有libc函数可供参考的解决方案
    │   └── yocto
    ├── ROP #RETURN-TO-LIBC
    │   ├── ret2plt
    │   ├── rop-1-overwirte retaddr_solved
    │   │   └── ret2plt
    │   ├── rop-2_solved
    │   ├── rop-3-infoleak&rop_solved
    │   ├── rop-4_solved
    │   └── ssctf_pwn250
    └── srop #如何利用中断指令直接完成操作而非利用函数
        ├── orw64_solved
        ├── orw_solved
        ├── orw_solved_solved
        ├── smallest-
        └── srop_test


```

### note
* GENERAL
> PWN根据计算机内存管理的两种方式分为stack相关题目和heap相关题目，heap的内存管理机制远比stack要复杂，最好的学习方式还是刷题，作者我在学习堆管理时候找不到难度适宜的入门题目因此走了很多弯路，这个题库中的题目不多，且非常基础，适合初学者第一次学习熟悉套路。
> 建议先从stack入手，按照SROP->ROP->fmt顺序学习


* heap_mix
> heap_mix中的题目由于记忆有些模糊，没有将题目根据方法分门别类，但是都是可以用unlink或者fastbin attack方式解决的，可以作为学习基本套路以后练手测试的题目



* FINAL
>推荐两个适合入门以后进一步学习的刷题平台

> <http://www.pwnable.kr> 脑洞较大，适合增长linux运维知识，以及一些奇诡的漏洞利用方式

> <http://www.pwnable.tw> 题目难度较大，很纯正的PWN赛题
