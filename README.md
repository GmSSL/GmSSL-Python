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

在安装过程中会产生`deprecated`警告，对于Python 3.11及之前的版本可忽略此警告，并可以顺利编译完成。

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
