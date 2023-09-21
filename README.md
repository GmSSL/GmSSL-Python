# GmSSL-Python

## 简介

`gmssl-python`是GmSSL密码库（https://gmssl.com/guanzhi/GmSSL）的Python语言封装，以`ctypes`方式实现，通过Python类和函数提供了如下密码接口：

* 密码随机数生成器
* SM2加密和签名，SM2密钥生成、私钥口令加密保护、密钥PEM文件导入导出
* SM2数字证书的导入、解析和验证
* SM3哈希函数、HMAC-SM3消息认证码、基于SM3的PBKDF2密钥导出函数
* SM4分组加密，以及SM4的CBC、CTR、GCM三种加密模式
* SM9加密和签名，以及SM9密钥生成、密钥口令加密保护、密钥PEM文件导入导出
* ZUC序列密码加密

目前`gmssl-python`功能可以覆盖除SSL/TLS/TLCP之外的国密算法主要应用开发场景。

## 安装

由于`gmssl-python`以`ctypes`方式实现，因此所有密码功能都是通过调用本地安装的GmSSL动态库 (如`/usr/local/lib/libgmssl.so`)实现的，在安装和调用`gmssl-python`之前必须首先在系统上安装GmSSL，然后通过Python的包管理工具`pip`从Python代码仓库安装，或者从`gmssl-python`项目的代码仓库https://github.com/GmSSL/GmSSL-Python 下载最新的源代码，从本地安装。

### 安装GmSSL

首先在https://github.com/guanzhi/GmSSL 项目上下载最新的GmSSL代码[GmSSL-master.zip](https://github.com/guanzhi/GmSSL/archive/refs/heads/master.zip)，编译并安装。GmSSL代码是C语言编写的，需要安装GCC、CMake来编译，在Ubuntu/Debian系统上可以执行

```bash
sudo install build-essentials cmake
```

安装依赖的编译工具，然后解压GmSSL源代码，进入源码目录`GmSSL-master`并执行如下指令：

```bash
$ mkdir build
$ cd build
$ cmake ..
$ make
$ make test
$ sudo make install
```

安装完成后可以执行`gmssl`命令行工具检查是否安装完毕。

```bash
$ gmssl help
```

由于`gmssl-python`需要`libgmssl`动态库，因此GmSSL安装时不要改变配置，仅以静态库安装时`gmssl-python`是不可用的。安装后执行`gmssl`命令可能提示找不到动态库，在Ubuntu系统下可以执行`sudo ldconfig`来发现新安装的动态库，在CentOS系统上需要在`/etc/ld.so.conf`配置文件中将`libgmssl`动态库的目录`/usr/local/lib`加入到配置文件中。

### 从Python代码仓库安装`gmssl-python`

`gmssl-python` 会定期发布到Python代码仓库中，可以通过`pip`工具安装

```bash
$ pip install gmssl-python
$ pip show gmssl-python
```

通过`pip show`命令可以查看当前安装的`gmssl-python`的版本信息。

### 下载源码本地安装

从代码仓库中安装的`gmssl-python`通常不是最新版本，可以下载最新的GmSSL-Python代码  [GmSSL-Python-main.zip](https://github.com/GmSSL/GmSSL-Python/archive/refs/heads/main.zip)，本地安装。

解压缩并进入源代码目录`GmSSL-Python-main`。由于最新代码可能还处于开发过程中，在安装前必须进行测试确保全部功能正确，`gmssl-python`中提供了测试，执行如下命令

运行测试

```bash
$ python -m unittest -v
................
----------------------------------------------------------------------
Ran 16 tests in 1.407s

OK
```

上面的输出表明测试通过。

然后可以通过`pip`命令安装当前目录下的代码

```bash
$ pip install .
$ pip show gmssl-python
```

### 验证安装成功

注意`gmssl-python`包中只包含一个`gmssl`模块（而不是`gmssl_python`模块）。

可以在Python交互环境中做简单的测试

```python
>>> import gmssl
>>> gmssl.GMSSL_PYTHON_VERSION
>>> gmssl.GMSSL_LIBRARY_VERSION
```

分别查看当前`gmssl-python`的版本和`libgmssl`的版本。

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





## 开发手册

### 随机数生成器

函数`rand_bytes`实现随机数生成功能。

```python
rand_bytes(size : int) -> bytes
```

输入参数`size` 是输出字节数组长度，返回值为`size`长度的随机字节数组。

通过`rand_bytes`方法生成的是具备密码安全性的随机数，可以用于密钥、IV或者其他随机数生成器的随机种子。

```python
>>> import gmssl
>>> key = gmssl.rand_bytes(16)
>>> print(key.hex())
```

`rand_bytes`是通过调用操作系统的密码随机数生成器（如`/dev/urandom`）实现的。由于底层操作系统的限制，在一次调用`rand_bytes`时不要指定明显超过密钥长度的输出长度，例如参数`size`的值不要超过128，否则可能导致阻塞，或者产生错误和异常。如果应用需要大量的随机数据，不应使用`rand_bytes`，而是应该考虑其他伪随机数生成算法。

需要注意的是，`rand_bytes`的安全性依赖于底层的操作系统随机数生成器的安全性。在服务器、笔记本等主流硬件和Windows、Linux、Mac主流服务器、桌面操作系统环境上，当计算机已经启动并且经过一段时间的用户交互和网络通信后，`rand_bytes`可以输出高质量的随机数。但是在缺乏用户交互和网络通信的嵌入式设备中，`rand_bytes`返回的随机数可能存在随机性不足的问题，在这些特殊的环境中，开发者需要提前或在运行时检测`rand_bytes`是否能够提供具有充分的随机性。

### SM3哈希

SM3密码杂凑函数可以将任意长度的输入数据计算为固定32字节长度的哈希值。

模块`gmssl`中包含如下SM3的常量

* `SM3_DIGEST_SIZE` 即SM3哈希值的字节长度

类`Sm3`实现了SM3功能，类`Sm3`的对象是由构造函数生成的

```
gmssl.Sm3()
```

对象sm3的方法：

* `sm3.update(data : bytes)` 要哈希的消息是通过`update`方法输入的，输入`data`的数据类型是`bytes`类型，如果输入的数据是字符串，需要通过字符串的`encode`方法转换成`bytes`，否则无法生成正确的哈希值。
* `sm3.digest() -> bytes` 在通过`update`输入完所有消息后，就可以通过`digest`方法获得输出的哈希值，输出的结果类型为`bytes`类型，长度为`SM3_DIGEST_SIZE`。
* `sm3.reset()` 在SM3对象完成一个消息的哈希后，可以通过`reset`方法重置对象状态，效果等同于构造函数，重置后可以通过`update`、`digest`计算新一个消息的哈希值。`reset`方法使得应用可以只创建一个`Sm3`的对象，计算任意数量的哈希值。

下面的例子展示了如何通过类`Sm3`计算字符串的SM3哈希值。

```Python
>>> from gmssl import *
>>> sm3 = Sm3()
>>> sm3.update(b'abc')
>>> sm3.digest().hex()
```

注意这里提供的消息字符串是`bytes`格式的。这个例子的源代码在`examples/sm3.py`文件中，编译并运行这个例子。

```bash
$ python examples/sm3.py
```

打印出的`66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`就是字符串`abc`的哈希值。字符串`abc`的哈希值也是SM3标准文本中给出的第一个测试数据，通过对比标准文本可以确定这个哈希值是正确的。

也可以通过`gmssl`命令行来验证`Sm3`类的计算是正确的。

```bash
$ echo -n abc | gmssl sm3
66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
```

可以看到输出的结果是一样。

注意，如果将字符串`abc`写入到文本文件中，文本编辑器通常会在文本结尾处增加格外的结束符，如`0x0a`字符，那么计算出的哈希值将不是上面的结果，比如可能是`12d4e804e1fcfdc181ed383aa07ba76cc69d8aedcbb7742d6e28ff4fb7776c34`。如果命令`echo`不使用`-n`的参数，也会出现同样的错误。这是很多开发者在初次进行哈希函数开发时容易遇到的错误，哈希函数的安全性质保证，即使输入的消息只差一个比特，那么输出的哈希值也完全不同。

如果需要哈希的数据来自于网络或者文件，那么应用可能需要多次读取才能获得全部的数据。在通过`Sm3`计算哈希值时，应用不需要通过保存一个缓冲区来保存全部的数据，而是可以通过多次调用`update`方法，将数据输入给`Sm3`对象，在数据全都输入完之后，最后调用`digest`方法得到全部数据的SM3哈希值。下面的代码片段展示了这一用法。

```python
>>> from gmssl import *
>>> sm3 = Sm3()
>>> sm3.update(b"Hello ")
>>> sm3.update(b"world!")
>>> dgst = sm3.digest()
```

这个例子中两次调用了`update`方法，效果等同于

```python
sm3.update(b"Hello world!");
```

注意，SM3算法也支持生成空数据的哈希值，因此下面的代码片段也是合法的。

```java
>>> from gmssl import *
>>> sm3 = Sm3()
>>> dgst = sm3.digest()
```

GmSSL-Python其他类的`update`方法通常也都提供了这种形式的接口。在输入完所有的数据之后，通过调用`digest`方法就可以获得所有输入数据的SM3哈希值了。`digest`方法输出的是长度为`SM3_DIGEST_SIZE`字节（即32字节）的二进制哈希值。

如果应用要计算多组数据的不同SM3哈希值，可以通过`reset`方法重置`Sm3`对象的状态，然后可以再次调用`update`和`digest`方法计算新一组数据的哈希值。这样只需要一个`Sm3`对象就可以完成多组哈希值的计算。

```python
>>> from gmssl import *
>>> sm3 = Sm3()
>>> sm3.update(b"abc")
>>> dgst1 = sm3.digest()
>>>
>>> sm3.reset()
>>> sm3.update(b"Hello ")
>>> sm3.update(b"world!")
>>> dgst2 = sm3.digest()
```

GmSSL-Python的部分其他类也提供了`reset`方法。









