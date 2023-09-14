# GmSSL-Python

## 简介

本项目是GmSSL密码库的Python语言封装。GmSSL-Python目前提供了随机数生成器、SM3哈希、SM3消息认证码(HMAC-SM3)、SM4加密（包括分组加密和CBC/CTR/GCM加密模式）、ZUC加密、SM2加密/签名等功能，可以覆盖目前国密算法主要应用开发场景。

## 编译和安装

GmSSL-Java依赖GmSSL项目，在编译前需要先在系统上编译、安装并测试通过GmSSL库及工具。请在https://github.com/guanzhi/GmSSL 项目上下载最新的GmSSL代码，并完成编译、测试和安装。

下载最新的GmSSL-Python代码  [GmSSL-Python-main.zip](https://github.com/GmSSL/GmSSL-Python/archive/refs/heads/main.zip)，解压缩，进入源代码目录。

首先创建源码安装包

```bash
python setup.py sdist
```

本地安装

```
python setup.py install
```

在安装过程中会产生`deprecated`警告，对于Python 3.11及之前的版本可忽略此警告，并可以顺利编译完成。

运行测试

```bash
$ python -m unittest
..........
----------------------------------------------------------------------
Ran 10 tests in 0.256s

OK
```

上面的输出表明测试通过。

编写一个简单的测试程序`sm3.py`

```python
from gmssl import *

sm3 = Sm3()
sm3.update(b'abc')
dgst = sm3.digest()
print("sm3('abc') : " + dgst.hex())
```

执行这个程序

```bash
$ python demo.py
sm3('abc') : 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

可以看到运行成功。通过`gmssl`命令行验证输出是正确的

```
echo -n abc | gmssl sm3
```

可以看到输出相同的SM3哈希值
