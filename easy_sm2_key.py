#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
# @Time: 2024-12-21 14:31:17

from __future__ import annotations

import base64
import binascii
import ctypes
from enum import Enum
from typing import Dict , List , Literal , Tuple

from pyasn1.codec.der import decoder , encoder
from pyasn1.type import namedtype , univ

from .gmssl import NativeError , SM2_MAX_CIPHERTEXT_SIZE , SM2_MAX_PLAINTEXT_SIZE , SM3_DIGEST_SIZE , Sm2Key


class SM2PubKeyASN1Sequence(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('oid-tags' ,
                                univ.Sequence(
                                        componentType = namedtype.NamedTypes(
                                                namedtype.NamedType('oid-1' , univ.ObjectIdentifier()) ,
                                                namedtype.NamedType('oid-2' , univ.ObjectIdentifier()) ,
                                                ) ,
                                        )) ,
            namedtype.NamedType('sm2_public_key' , univ.BitString()) ,
            )


class SM2PubKeyRawData(object):
    def __init__(self , oids: List[ str ] , hex_data: str):
        self.__oids = oids
        self.__hex_data = hex_data
    
    @property
    def oids(self) -> List[ str ]:
        return self.__oids
    
    @property
    def hex_data(self) -> str:
        return self.__hex_data


class SM2CipherMode(Enum):
    C1C3C2_ASN1 = 'C1C3C2_ASN1'
    C1C3C2 = 'C1C3C2'
    C1C2C3_ASN1 = 'C1C2C3_ASN1'
    C1C2C3 = 'C1C2C3'


class SM2CipherFormat(Enum):
    Base64Str = 'Base64'
    HexStr = 'Hex'


class SM2CipherLength(Enum):
    """
    SM2密文主要由C1、C2、C3三部分构成，
    其中C1是随机数计算出的椭圆曲线、C2是密文数据、C3是SM3杂凑值，
    C1固定为64字节，C2的长度与明文相同，C3的长度固定为32字节，
    """
    C1LenInBytes = 64
    C1XLenInBytes = 32
    C1YLenInBytes = 32
    C3LenInBytes = 32


def __easy_parse_sm2_pub_key__(base64_content: str) -> SM2PubKeyRawData:
    try:
        raw_bytes = base64.b64decode(base64_content)
        ret_obj , _ = decoder.decode(raw_bytes , asn1Spec = SM2PubKeyASN1Sequence())
    except Exception:
        raise ValueError('invalid sm2 public key bytes')
    else:
        oid1 = ret_obj[ 'oid-tags' ][ 'oid-1' ].prettyPrint()
        oid2 = ret_obj[ 'oid-tags' ][ 'oid-2' ].prettyPrint()
        sm2_pub = ret_obj[ 'sm2_public_key' ]
        bit_string = sm2_pub.asOctets()
        hex_string = binascii.hexlify(bit_string).decode('utf-8')
        return SM2PubKeyRawData([ oid1 , oid2 ] , hex_string)


def __check_private_key_password__(pri_key_password: str):
    if len(pri_key_password) <= 0:
        raise ValueError('empty password for sm2 private key')
    if len(pri_key_password) > 32:
        raise ValueError('sm2 private key password too long')


def __easy_read_sm2_pub_pem_file_lines__(pem_file: str) -> str:
    """
    返回 base64 编码的公钥内容
    """
    MAX_FILE_SIZE = 2048
    file_size = 0
    lines = [ ]
    try:
        with open(pem_file , 'r') as pem_file:
            for line in pem_file:
                file_size += len(line)
                if file_size > MAX_FILE_SIZE:
                    raise ValueError("PEM File Too Large")
                lines.append(line.strip())
    except FileNotFoundError:
        raise FileNotFoundError("invalid file:{}".format(pem_file))
    else:
        content = ''
        for i in lines:
            i = i.strip()
            if len(i) > 0:
                content += i.strip()
        content = content.replace('-----BEGIN PUBLIC KEY-----' , '')
        content = content.replace('-----END PUBLIC KEY-----' , '')
        if len(content) <= 0:
            raise ValueError("invalid pem content")
        return content


# 定义SM2 C1C3C2_ASN1 Ciphertext结构
class SM2_C1C3C2_ASN1_Ciphertext(univ.Sequence):
    """
    c1x 和 c1y 分别代表 C1 点的 x 和 y 坐标
    这个 C1 点是加密过程中随机生成的，用于与接收方的公钥进行交互以确保加密的安全性
    C1 的坐标（c1x, c1y）与公钥的坐标（x, y）是不会相同的
    在实际应用中，随机数 k 是每次加密时新生成的随机数，以确保加密的安全性
    """
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('c1x' , univ.Integer()) ,
            namedtype.NamedType('c1y' , univ.Integer()) ,
            namedtype.NamedType('c3' , univ.OctetString()) ,
            namedtype.NamedType('c2' , univ.OctetString()) ,
            )


# 定义SM2 C1C2C3_ASN1 Ciphertext结构
class SM2_C1C2C3_ASN1_Ciphertext(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('c1x' , univ.Integer()) ,
            namedtype.NamedType('c1y' , univ.Integer()) ,
            namedtype.NamedType('c2' , univ.OctetString()) ,
            namedtype.NamedType('c3' , univ.OctetString()) ,
            )


def __check_raw_cipher_length__(raw_cipher: bytes):
    min_length = SM2CipherLength.C1LenInBytes.value + SM2CipherLength.C3LenInBytes.value
    if len(raw_cipher) < min_length:
        raise ValueError('invalid cipher length, required at least:{} bytes'.format(min_length))
    return


def __parse_sm2_asn1_cipher_bytes__(raw_cipher: bytes ,
                                    cipher_mode: Literal[
                                        SM2CipherMode.C1C3C2_ASN1 , SM2CipherMode.C1C2C3_ASN1 ] =
                                    SM2CipherMode.C1C3C2_ASN1) -> \
        Tuple[
            bytes , bytes , bytes , bytes ]:
    """
    解析 C1C3C2_ASN1 或 C1C2C3_ASN1 格式的密文数据，返回 C1X、C1Y、C3、C2 字节序列
    """
    if cipher_mode not in [ SM2CipherMode.C1C3C2_ASN1 , SM2CipherMode.C1C2C3_ASN1 ]:
        raise ValueError('invalid sm2 cipher mode:{}'.format(cipher_mode))
    asn1SpecObj = SM2_C1C3C2_ASN1_Ciphertext()
    if cipher_mode == SM2CipherMode.C1C2C3_ASN1:
        asn1SpecObj = SM2_C1C2C3_ASN1_Ciphertext()
    try:
        __check_raw_cipher_length__(raw_cipher)
        decoded , _ = decoder.decode(raw_cipher , asn1Spec = asn1SpecObj)
    except Exception:
        raise ValueError('invalid ASN1 cipher data')
    else:
        # print(decoded)
        c1x = int(decoded[ 'c1x' ])  # 大整数
        c1y = int(decoded[ 'c1y' ])  # 大整数
        c2 = bytes(decoded[ 'c2' ])  # 字节流
        c3 = bytes(decoded[ 'c3' ])  # 字节流
        # 大端字节序
        c1x_bytes = c1x.to_bytes(length = 32 , byteorder = 'big')
        c1y_bytes = c1y.to_bytes(length = 32 , byteorder = 'big')
        return c1x_bytes , c1y_bytes , c3 , c2


def __encode_sm2_cipher_to_asn1_sequence__(cipher_c1c3c2: Tuple[ bytes , bytes , bytes , bytes ] ,
                                           cipher_mode: Literal[
                                               SM2CipherMode.C1C3C2_ASN1 , SM2CipherMode.C1C2C3_ASN1 ] =
                                           SM2CipherMode.C1C3C2_ASN1) -> bytes:
    if cipher_mode not in [ SM2CipherMode.C1C3C2_ASN1 , SM2CipherMode.C1C2C3_ASN1 ]:
        raise ValueError('invalid sm2 cipher mode:{}'.format(cipher_mode))
    try:
        c1x = cipher_c1c3c2[ 0 ]
        c1x_int = int.from_bytes(c1x , byteorder = 'big')
        c1y = cipher_c1c3c2[ 1 ]
        c1y_int = int.from_bytes(c1y , byteorder = 'big')
        c3 = cipher_c1c3c2[ 2 ]
        c2 = cipher_c1c3c2[ 3 ]
    except Exception as e:
        raise ValueError('invalid sm2 cipher data:{}'.format(e))
    else:
        ciphertext = SM2_C1C3C2_ASN1_Ciphertext()
        if cipher_mode == SM2CipherMode.C1C2C3_ASN1:
            ciphertext = SM2_C1C2C3_ASN1_Ciphertext()
        ciphertext.setComponentByName('c1x' , c1x_int)
        ciphertext.setComponentByName('c1y' , c1y_int)
        ciphertext.setComponentByName('c3' , c3)
        ciphertext.setComponentByName('c2' , c2)
        encoded_ciphertext = encoder.encode(ciphertext)
        return encoded_ciphertext


def __parse_sm2_c1c3c2_cipher_bytes__(raw_cipher: bytes) -> Tuple[ bytes , bytes , bytes , bytes ]:
    """
    解析 C1C3C2 格式的密文数据，返回 C1X、C1Y、C3、C2 字节序列
    """
    try:
        __check_raw_cipher_length__(raw_cipher)
        c1x_bytes = raw_cipher[ :SM2CipherLength.C1XLenInBytes.value ]
        c1y_bytes = raw_cipher[
                    SM2CipherLength.C1XLenInBytes.value: SM2CipherLength.C1XLenInBytes.value +
                                                         SM2CipherLength.C1YLenInBytes.value ]
        c3_bytes = raw_cipher[ SM2CipherLength.C1XLenInBytes.value + SM2CipherLength.C1YLenInBytes.value:
                               SM2CipherLength.C1XLenInBytes.value + SM2CipherLength.C1YLenInBytes.value +
                               SM2CipherLength.C3LenInBytes.value ]
        c2_bytes = raw_cipher[
                   SM2CipherLength.C1XLenInBytes.value + SM2CipherLength.C1YLenInBytes.value +
                   SM2CipherLength.C3LenInBytes.value: ]
    except Exception as e:
        raise ValueError('invalid sm2 cipher data:{}'.format(e))
    else:
        return c1x_bytes , c1y_bytes , c3_bytes , c2_bytes


def __parse_sm2_c1c2c3_bytes__(raw_cipher: bytes) -> Tuple[ bytes , bytes , bytes , bytes ]:
    """
    解析 C1C2C3 格式的密文数据，返回 C1X、C1Y、C3、C2 字节序列
    """
    try:
        __check_raw_cipher_length__(raw_cipher)
        c1x_bytes = raw_cipher[ :SM2CipherLength.C1XLenInBytes.value ]
        c1y_bytes = raw_cipher[
                    SM2CipherLength.C1XLenInBytes.value: SM2CipherLength.C1XLenInBytes.value +
                                                         SM2CipherLength.C1YLenInBytes.value ]
        c3_bytes = raw_cipher[ len(raw_cipher) - SM2CipherLength.C3LenInBytes.value: ]
        c2_bytes = raw_cipher[ SM2CipherLength.C1XLenInBytes.value + SM2CipherLength.C1YLenInBytes.value:len(
                raw_cipher) - SM2CipherLength.C3LenInBytes.value ]
    except Exception as e:
        raise ValueError('invalid sm2 cipher data:{}'.format(e))
    else:
        return c1x_bytes , c1y_bytes , c3_bytes , c2_bytes


def __encode_cipher__(target_mode: SM2CipherMode , cipher_c1c3c2: Tuple[ bytes , bytes , bytes , bytes ]) -> bytes:
    """
    将 C1X C1Y C3 C2 密文字节序列编码成指定的 SM2 密文格式
    如果是 ASN1 格式，则需要单独做二进制编码
    如果是非 ASN1 格式，则只需要按照指定的顺序将 C1、C3、C2进行拼接
    """
    try:
        c1x = cipher_c1c3c2[ 0 ]
        c1y = cipher_c1c3c2[ 1 ]
        c3 = cipher_c1c3c2[ 2 ]
        c2 = cipher_c1c3c2[ 3 ]
    except Exception as e:
        raise ValueError('invalid cipher data:{}'.format(e))
    else:
        ret = bytearray()
        if target_mode == SM2CipherMode.C1C2C3:
            ret.extend(c1x)
            ret.extend(c1y)
            ret.extend(c2)
            ret.extend(c3)
            return bytes(ret)
        elif target_mode == SM2CipherMode.C1C3C2:
            ret.extend(c1x)
            ret.extend(c1y)
            ret.extend(c3)
            ret.extend(c2)
            return bytes(ret)
        else:
            try:
                if target_mode in [ SM2CipherMode.C1C3C2_ASN1 , SM2CipherMode.C1C2C3_ASN1 ]:
                    return __encode_sm2_cipher_to_asn1_sequence__(cipher_c1c3c2 = cipher_c1c3c2 ,
                                                                  cipher_mode = target_mode)
                else:
                    raise TypeError('invalid cipher mode:{}'.format(target_mode))
            except Exception as e:
                raise ValueError('encode cipher to asn1 mode:{} error:{}'.format(target_mode , e))


def __parse_and_repack_cipher__(cipher_mode: SM2CipherMode ,
                                cipher_format: SM2CipherFormat ,
                                c1c3c2_asn1_cipher: bytes) -> str:
    if not isinstance(cipher_mode , SM2CipherMode):
        raise TypeError('invalid cipher mode: {}'.format(cipher_mode))
    if not isinstance(cipher_format , SM2CipherFormat):
        raise TypeError('invalid cipher format: {}'.format(cipher_format))
    encoded_cipher_bytes = c1c3c2_asn1_cipher
    if cipher_mode != SM2CipherMode.C1C3C2_ASN1:
        # 首先按照C1C3C2_ASN1格式解析原始的数据，获取到 C1X、C1Y、C3、C2这四部分数据
        cipher_c1_c3_c2 = __parse_sm2_asn1_cipher_bytes__(raw_cipher = c1c3c2_asn1_cipher ,
                                                          cipher_mode = SM2CipherMode.C1C3C2_ASN1)
        encoded_cipher_bytes = __encode_cipher__(target_mode = cipher_mode , cipher_c1c3c2 = cipher_c1_c3_c2)
    
    if cipher_format == SM2CipherFormat.Base64Str:
        return base64.b64encode(encoded_cipher_bytes).decode('utf-8')
    else:
        return encoded_cipher_bytes.hex()


def __parse_raw_cipher_and_repack_to_c1c3c2_asn1__(cipher_mode: Literal[
    SM2CipherMode.C1C3C2_ASN1 ,
    SM2CipherMode.C1C3C2 ,
    SM2CipherMode.C1C2C3_ASN1 ,
    SM2CipherMode.C1C2C3 ] ,
                                                   raw_cipher_bytes: bytes) -> bytes:
    """
    将不同模式下的密文数据统一转换为 C1C3C2_ASN1 模式的密文
    """
    try:
        __check_raw_cipher_length__(raw_cipher_bytes)
        c1_c3_c2_bytes = bytes()
        if cipher_mode == SM2CipherMode.C1C3C2_ASN1:
            return raw_cipher_bytes
        elif cipher_mode == SM2CipherMode.C1C2C3_ASN1:
            c1_c3_c2_bytes = __parse_sm2_asn1_cipher_bytes__(raw_cipher = raw_cipher_bytes , cipher_mode = cipher_mode)
        elif cipher_mode == SM2CipherMode.C1C2C3:
            c1_c3_c2_bytes = __parse_sm2_c1c2c3_bytes__(raw_cipher = raw_cipher_bytes)
        elif cipher_mode == SM2CipherMode.C1C3C2:
            c1_c3_c2_bytes = __parse_sm2_c1c3c2_cipher_bytes__(raw_cipher = raw_cipher_bytes)
    except Exception as e:
        raise ValueError('invalid cipher data:{}, cipher mode = {}'.format(e , cipher_mode))
    else:
        return __encode_cipher__(target_mode = SM2CipherMode.C1C3C2_ASN1 , cipher_c1c3c2 = c1_c3_c2_bytes)


class EasySm2Key(object):
    """
    EasySM2Key 对象非线程安全，不可并发执行写操作
    """
    
    def __init__(self):
        self._point_x = ''
        self._point_y = ''
        self._private_key_hex = ''
        self._sm2_raw_key = Sm2Key()
        self.reset_key()
        self.new_key()
    
    def reset_key(self):
        """
        清理 key 数据
        清理后可以使用 new_key() 生成新的 SM2密钥对数据
        """
        self.__clear_raw_key_data__()
    
    def __clear_raw_key_data__(self):
        # 清空数据
        ctypes.memset(ctypes.byref(self._sm2_raw_key.public_key.x) , 0 , 32)
        ctypes.memset(ctypes.byref(self._sm2_raw_key.public_key.y) , 0 , 32)
        ctypes.memset(ctypes.byref(self._sm2_raw_key.private_key) , 0 , 32)
        self._point_x = ''
        self._point_y = ''
        self._private_key_hex = ''
        self._sm2_raw_key._has_public_key = False
        self._sm2_raw_key._has_private_key = False
    
    def __set_point_x_y_in_hex__(self):
        if self._sm2_raw_key.has_public_key():
            self._point_x = bytes(self._sm2_raw_key.public_key.x).hex()
            self._point_y = bytes(self._sm2_raw_key.public_key.y).hex()
    
    def __set_private_key_in_hex__(self):
        if self._sm2_raw_key.has_private_key():
            self._private_key_hex = bytes(self._sm2_raw_key.private_key).hex()
    
    def new_key(self) -> EasySm2Key:
        """
        用于在使用 reset_key() 后重新生成新的 SM2 密钥对
        """
        self.__clear_raw_key_data__()
        self._sm2_raw_key.generate_key()
        self.__set_point_x_y_in_hex__()
        self.__set_private_key_in_hex__()
        return self
    
    def export_to_pem_file(self , file_name_prefix: str , pri_key_password: str):
        """
        输入：文件名前缀、私钥密码
        假设文件名前缀为 test, 则生成的文件名为: test_sm2_public.pem、test_sm2_private.pem
        私钥密码不能为空，最长允许 32 个字节
        """
        if len(file_name_prefix) <= 0:
            raise ValueError('empty sm2 file name prefix')
        pub_key_file_name = f'{file_name_prefix}_sm2_public.pem'
        pri_key_file_name = f'{file_name_prefix}_sm2_private.pem'
        try:
            __check_private_key_password__(pri_key_password)
            self._sm2_raw_key.export_public_key_info_pem(pub_key_file_name)
            self._sm2_raw_key.export_encrypted_private_key_info_pem(pri_key_file_name , pri_key_password)
        except Exception as e:
            raise e
    
    def load_sm2_pub_key(self , pub_key_file: str) -> SM2PubKeyRawData:
        """
        从 PEM 文件中加载 SM2 公钥
        """
        try:
            base64_content_data = __easy_read_sm2_pub_pem_file_lines__(pub_key_file)
            sm2_pub_raw_data = __easy_parse_sm2_pub_key__(base64_content_data)
        except Exception:
            raise ValueError('invalid sm2 public key file')
        else:
            self.__clear_raw_key_data__()
            self._sm2_raw_key.import_public_key_info_pem(pub_key_file)
            self.__set_point_x_y_in_hex__()
            assert sm2_pub_raw_data.hex_data == self.__get_pub_key_by_point__()
            return sm2_pub_raw_data
    
    def load_sm2_private_key(self , pri_key_file: str , password: str):
        """
        从 PEM 文件中加载 SM2 私钥，加载的私钥必须要输入解密密码
        加载密钥时会重置公钥和私钥数据
        """
        try:
            __check_private_key_password__(password)
            self._sm2_raw_key.import_encrypted_private_key_info_pem(pri_key_file , password)
        except NativeError as e:
            raise ValueError('invalid sm2 private key file or password, {}'.format(e))
        except Exception:
            raise TypeError('sm2 pem private key imported failed')
        else:
            self.__set_point_x_y_in_hex__()
            self.__set_private_key_in_hex__()
    
    def __get_pub_key_by_point__(self , uncompressed: bool = True) -> str:
        """
        在 SM2 公钥十六进制表示中，前导字节04表示该公钥是非压缩形式。
        SM2 公钥是椭圆曲线上的一个点，由横坐标X和纵坐标Y两个分量组成。
        非压缩形式的公钥直接存储了完整的X和Y坐标值，其格式为04||X||Y ，其中X和Y均为 32 字节

        如果公钥是压缩形式，公钥的表示以字节 02 或者 03 开头
        """
        if self._sm2_raw_key.has_public_key():
            if uncompressed:
                return '04' + self._point_x + self._point_y
            else:
                raise TypeError('SM2 Public Key in compressed form are not supported')
        return ''
    
    def get_sm2_public_key_in_hex(self) -> str:
        """
        返回公钥的十六进制字符串
        如果没有公钥, 则返回的字符串为空
        """
        if self._sm2_raw_key.has_public_key():
            return self.__get_pub_key_by_point__()
        return ''
    
    def get_sm2_private_key_in_hex(self) -> str:
        """
        返回私钥的十六进制字符串
        如果没有私钥，则返回的字符串为空
        """
        if self._sm2_raw_key.has_public_key():
            return self._private_key_hex
        return ''
    
    def get_point_in_hex(self) -> Dict[ str , str ]:
        """
        返回 [X, Y] 坐标的十六进制字符串
        如果没有公钥，则返回的坐标值为空
        """
        if self._sm2_raw_key.has_public_key():
            return { 'X':self._point_x , 'Y':self._point_y }
        return { 'X':'' , 'Y':'' }
    
    def get_z(self) -> bytes:
        """
        计算用于SM2签名的SM3摘要过程
            1. 使用公钥和userid计算z值
            2. 将z值和消息原文msg拼接：得到z||msg
            3. 计算z||msg的SM3摘要值
        """
        if not self._sm2_raw_key.has_public_key():
            raise ValueError('need SM2 Public Key')
        return self._sm2_raw_key.compute_z()
    
    def sign_digest(self , digest: bytes) -> bytes:
        if not self._sm2_raw_key.has_private_key():
            raise ValueError('need SM2 Private Key')
        if len(digest) != SM3_DIGEST_SIZE:
            raise ValueError(f'Invalid SM3 digest size, should be {SM3_DIGEST_SIZE} bytes')
        return self._sm2_raw_key.sign(digest)
    
    def verify_digest_signature(self , digest: bytes , signature: bytes) -> bool:
        if not self._sm2_raw_key.has_public_key():
            raise ValueError('need SM2 Public Key')
        if len(digest) != SM3_DIGEST_SIZE:
            raise ValueError('Invalid SM3 digest size, should be {SM3_DIGEST_SIZE} bytes')
        return self._sm2_raw_key.verify(digest , signature)


class EasySm2EncryptionKey(EasySm2Key):
    def __init__(self):
        super().__init__()
    
    def Encrypt(self , plain_data: bytes ,
                cipher_mode: Literal[
                    SM2CipherMode.C1C3C2_ASN1 ,
                    SM2CipherMode.C1C3C2 ,
                    SM2CipherMode.C1C2C3_ASN1 ,
                    SM2CipherMode.C1C2C3 ] = SM2CipherMode.C1C3C2_ASN1 ,
                cipher_format: Literal[
                    SM2CipherFormat.Base64Str ,
                    SM2CipherFormat.HexStr ] = SM2CipherFormat.Base64Str) -> str:
        if not isinstance(cipher_mode , SM2CipherMode):
            raise TypeError('invalid cipher mode: {}'.format(cipher_mode))
        if not isinstance(cipher_format , SM2CipherFormat):
            raise TypeError('invalid cipher format: {}'.format(cipher_format))
        if self._sm2_raw_key.has_public_key():
            if len(plain_data) <= SM2_MAX_PLAINTEXT_SIZE:
                c1c3c2_asn1_cipher_bytes: bytes = self._sm2_raw_key.encrypt(plain_data)
                return __parse_and_repack_cipher__(cipher_mode , cipher_format , c1c3c2_asn1_cipher_bytes)
            else:
                raise ValueError('the maximum limit for the plaintext is {} bytes'.format(SM2_MAX_PLAINTEXT_SIZE))
        else:
            raise ValueError('empty sm2 public key')
    
    def Decrypt(self , cipher_data: bytes ,
                cipher_mode: Literal[
                    SM2CipherMode.C1C3C2_ASN1 ,
                    SM2CipherMode.C1C3C2 ,
                    SM2CipherMode.C1C2C3_ASN1 ,
                    SM2CipherMode.C1C2C3 ] = SM2CipherMode.C1C3C2_ASN1) -> bytes:
        """
        cipher_data: 密文数据
        cipher_mode: 密文模式
        返回明文的字节序列
        """
        if not isinstance(cipher_mode , SM2CipherMode):
            raise TypeError('invalid cipher mode: {}'.format(cipher_mode))
        if not self._sm2_raw_key.has_private_key():
            raise TypeError('no private key included, can not decrypt')
        if len(cipher_data) > SM2_MAX_CIPHERTEXT_SIZE:
            raise ValueError(
                    'cipher data too long, the maximum limit for the cipher is {} bytes'.format(
                            SM2_MAX_CIPHERTEXT_SIZE))
        try:
            to_be_decrypted_cipher = __parse_raw_cipher_and_repack_to_c1c3c2_asn1__(cipher_mode = cipher_mode ,
                                                                                    raw_cipher_bytes = cipher_data)
            ret = bytes(self._sm2_raw_key.decrypt(to_be_decrypted_cipher))
        except Exception as e:
            raise ValueError('decrypt error:{}, cipher mode = {}'.format(e , cipher_mode))
        else:
            return ret