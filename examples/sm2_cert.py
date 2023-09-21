# Copyright 2023 The GmSSL Project. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the License); you may
# not use this file except in compliance with the License.
#
# http://www.apache.org/licenses/LICENSE-2.0

from gmssl import *

cert_txt = '''\
-----BEGIN CERTIFICATE-----
MIIBszCCAVegAwIBAgIIaeL+wBcKxnswDAYIKoEcz1UBg3UFADAuMQswCQYDVQQG
EwJDTjEOMAwGA1UECgwFTlJDQUMxDzANBgNVBAMMBlJPT1RDQTAeFw0xMjA3MTQw
MzExNTlaFw00MjA3MDcwMzExNTlaMC4xCzAJBgNVBAYTAkNOMQ4wDAYDVQQKDAVO
UkNBQzEPMA0GA1UEAwwGUk9PVENBMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE
MPCca6pmgcchsTf2UnBeL9rtp4nw+itk1Kzrmbnqo05lUwkwlWK+4OIrtFdAqnRT
V7Q9v1htkv42TsIutzd126NdMFswHwYDVR0jBBgwFoAUTDKxl9kzG8SmBcHG5Yti
W/CXdlgwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwHQYDVR0OBBYEFEwysZfZ
MxvEpgXBxuWLYlvwl3ZYMAwGCCqBHM9VAYN1BQADSAAwRQIgG1bSLeOXp3oB8H7b
53W+CKOPl2PknmWEq/lMhtn25HkCIQDaHDgWxWFtnCrBjH16/W3Ezn7/U/Vjo5xI
pDoiVhsLwg==
-----END CERTIFICATE-----'''
with open('ROOTCA.pem', 'w') as file:
	file.write(cert_txt)
	file.close()

cert = Sm2Certificate()
cert.import_pem('ROOTCA.pem')

print("Certificate")

serial = cert.get_serial_number()
print("Serial :", serial.hex())

validity = cert.get_validity()
print("Validity.notBefore :", validity.not_before)
print("Validity.notAfter :", validity.not_after)

issuer = cert.get_issuer()
print("Issuer :")
for key in issuer:
	if key == 'raw_data':
		print("    ", key, ":", issuer[key].hex())
	else:
		print("    ", key, ":", issuer[key])


subject = cert.get_subject()
print("Subject :")
for key in subject:
	if key == 'raw_data':
		print("    ", key, ":", subject[key].hex())
	else:
		print("    ", key, ":", subject[key])

public_key = cert.get_subject_public_key()
public_key.export_public_key_info_pem('subject_public_key.pem')

file = open('subject_public_key.pem',mode='r')
fulltext = file.read()
file.close()
print("Subject Public Key:")
print(fulltext)


