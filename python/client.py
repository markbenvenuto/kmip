import ssl
from kmip.pie.client import ProxyKmipClient
#from kmip.core.enums import KMIPVersion
from  kmip.core import enums

client = ProxyKmipClient(
    hostname='127.0.0.1',
    port=5696,
    cert='../test_data/client.pem',
    key='../test_data/client.key',
    ca='../test_data/ca.pem',
    #ssl_version=ssl.PROTOCOL_TLSv1,
    # username='example_username',
    # password='example_password'
    #config='client',
    #config_file='pykmip.conf',
    #kmip_version=KMIPVersion.KMIP_1_2
)

print("Connecting...")
client.open()

key_id = client.create(
    enums.CryptographicAlgorithm.AES,
    128,
    #operation_policy_name='default',
    #name='Test_256_AES_Symmetric_Key',
    # cryptographic_usage_mask=[
    #     enums.CryptographicUsageMask.ENCRYPT,
    #     enums.CryptographicUsageMask.DECRYPT
    # ]
)

print("Getting key")
print(client.get(key_id))

print("Get attributes")
print(client.get_attributes(key_id))

print("Get attribute list")
print(client.get_attribute_list(key_id))

print("Activate")
print(client.activate(key_id))

print("Encrypt")
print(client.encrypt(b"1234567812345678", uid=key_id, iv_counter_nonce = b'1234567812345678', cryptographic_parameters = { 'block_cipher_mode': enums.BlockCipherMode.CBC}))

print("Revoke")
print(client.revoke(enums.RevocationReasonCode.UNSPECIFIED, key_id))

print("Destroy")
print(client.destroy(key_id))

