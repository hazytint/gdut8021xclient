gdut8021xclient
=========

广东某工业大学802.1X客户端

项目简介
---
本项目修改自njit8021xclient

编译安装
---

下载源代码

```
git clone https://github.com/hazytint/gdut8021xclient.git
cd gdut8021xclient/
autoreconf --install    #从GitHub下载的代码第一次编译时必须先执行以下命令以生成configure脚本
```

编译

```
./configure
make
```

安装

```
make install
```

使用方法
---

```
sudo njit-client [username] [password] [interface]
```

帮助文档
---
* [编译及安装](../master/Install.html)
* [原项目简介](../master/ReadMe.html)
* [原项目文档](../master/Documents.html)

Copyright (C) 2013, by hazytint
