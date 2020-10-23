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
    256,
    #operation_policy_name='default',
    #name='Test_256_AES_Symmetric_Key',
    # cryptographic_usage_mask=[
    #     enums.CryptographicUsageMask.ENCRYPT,
    #     enums.CryptographicUsageMask.DECRYPT
    # ]
)

print(client.get(key_id))

