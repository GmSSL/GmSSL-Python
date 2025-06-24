import os
import random
import unittest

from gmssl import SM2_MAX_SIGNATURE_SIZE
from .easy_sm2_sign_key import EasySM2SignKey , EasySM2VerifyKey , SignatureMode


class MyTestCase(unittest.TestCase):
    def setUp(self):
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        target_dir = 'test_keys'
        self.full_target_dir = self.current_dir + '/' + target_dir + '/'
        print(self.full_target_dir)
    
    def test_sign_data(self):
        signer_id = 'test_signer'
        print('signer_id hex:' , signer_id.encode('utf-8').hex())
        
        test = EasySM2SignKey(signer_id = signer_id ,
                              pem_private_key_file = self.full_target_dir + 'tmp_test_sm2_private.pem' ,
                              password = '123456')
        plain = bytes([ random.randint(0 , 255) for _ in range(0 , 64) ])
        print('plain hex:' , plain.hex())
        print('private key hex:' , test.get_sm2_private_key_in_hex())
        print('public key hex:' , test.get_sm2_public_key_in_hex())
        test.UpdateData(plain)
        sign_value = test.GetSignValue()
        print('signature hex:' , sign_value.hex())
        self.assertTrue(len(sign_value) <= SM2_MAX_SIGNATURE_SIZE)
        self.assertTrue(len(sign_value) >= 64)  # RS_ASN1 模式下的签名不小于 64 字节
        
        verify_test = EasySM2VerifyKey(signer_id = signer_id ,
                                       pem_public_key_file = self.full_target_dir + 'tmp_test_sm2_public.pem')
        print('verify public key:' , verify_test.get_sm2_public_key_in_hex())
        verify_test.UpdateData(plain)
        ret = verify_test.VerifySignature(sign_value)
        self.assertTrue(ret is True)
    
    def test_rs_sign_mode(self):
        signer_id = 'test_signer'
        print('signer_id hex:' , signer_id.encode('utf-8').hex())
        test = EasySM2SignKey(signer_id = signer_id ,
                              pem_private_key_file = self.full_target_dir + 'tmp_test_sm2_private.pem' ,
                              password = '123456')
        plain = bytes([ random.randint(0 , 255) for _ in range(0 , 64) ])
        print('plain hex:' , plain.hex())
        print('private key hex:' , test.get_sm2_private_key_in_hex())
        print('public key hex:' , test.get_sm2_public_key_in_hex())
        test.UpdateData(plain)
        
        sign_value = test.GetSignValue(signature_mode = SignatureMode.RS)
        print('signature hex:' , sign_value.hex())
        self.assertTrue(len(sign_value) <= SM2_MAX_SIGNATURE_SIZE)
        self.assertTrue(len(sign_value) == 64)
        
        verify_test = EasySM2VerifyKey(signer_id = signer_id ,
                                       pem_public_key_file = self.full_target_dir + 'tmp_test_sm2_public.pem')
        print('verify public key:' , verify_test.get_sm2_public_key_in_hex())
        verify_test.UpdateData(plain)
        ret = verify_test.VerifySignature(sign_value , signature_mode = SignatureMode.RS)
        self.assertTrue(ret is True)
    
    def test_invalid_sign_mode(self):
        signer_id = 'test_signer'
        test = EasySM2SignKey(signer_id = signer_id ,
                              pem_private_key_file = self.full_target_dir + 'tmp_test_sm2_private.pem' ,
                              password = '123456')
        plain = bytes([ random.randint(0 , 255) for _ in range(0 , 64) ])
        try:
            test.UpdateData(plain)
            test.GetSignValue(signature_mode = SignatureMode('abc'))
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
    
    def test_invalid_signature_size(self):
        signer_id = 'test_signer'
        plain = bytes([ random.randint(0 , 255) for _ in range(0 , 64) ])
        verify_test = EasySM2VerifyKey(signer_id = signer_id ,
                                       pem_public_key_file = self.full_target_dir + 'tmp_test_sm2_public.pem')
        print('verify public key:' , verify_test.get_sm2_public_key_in_hex())
        verify_test.UpdateData(plain)
        
        # RS_ASN1 模式下的签名长度最长为 72 字节
        test_sign_value = bytes([ random.randint(0 , 255) for _ in range(0 , SM2_MAX_SIGNATURE_SIZE + 1) ])
        try:
            ret = verify_test.VerifySignature(test_sign_value)
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)
        
        # RS 模式下的签名固定为 64 字节
        test_sign_value = bytes([ random.randint(0 , 255) for _ in range(0 , 64 + 1) ])
        try:
            ret = verify_test.VerifySignature(test_sign_value , signature_mode = SignatureMode.RS)
        except Exception as e:
            self.assertTrue(True)
            print(e)
        else:
            self.assertTrue(False)


if __name__ == '__main__':
    unittest.main()
