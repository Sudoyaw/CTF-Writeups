# Walkthroughs/Writeup

This is the challenge walkthroughs/writeup for the **2024 3108 CTF Kembara Tuah**

The competition was dated at 30-08-24 and it lasted for a total of 24 hours. The theme for this year's competition was around the states of Malaysia and the challenges were all related to them one way or two.  

It was a really unique and fun experience as this was my first time participating the `3108` CTF and I am really looking forward for this competition in the upcoming years. 

I've successfully secured 43rd place in this competition and here are my solutions to the challenges I managed to solve throughout the competition.

![Untitled](Attachments/Pasted%20image%2020240902220800.png)

![Untitled](Attachments/Pasted%20image%2020240902220814.png)



## Linux 🐧
Unfortunately there weren't much Linux challenges as I was really looking forwards to them 🫠

### Makanan Popular
![Untitled](Attachments/Pasted%20image%2020240902171805.png)

The downloaded file was an executable with non printable characters:
![Untitled](Attachments/Pasted%20image%2020240902172111.png)

With this, we can make use of `strings` in attempt to get the printable characters and look for the flag from within the file:
![Untitled](Attachments/Pasted%20image%2020240902172226.png)


### Cer Cari
![Untitled](Attachments/Pasted%20image%2020240902172324.png)

The question is hinting us towards an important date for Sabah. 
The file contains several lines of data that is wrapped in the flag format. I tried to find any anomaly among them but failed.

![Untitled](Attachments/Pasted%20image%2020240902172702.png)

A quick google search showed that one important day for Sabah is their independence day, 1963. The flag for this challenge was `3108{S4b4h_1963}`

---
## Cryptography 🧮
Now I'm no expert when it comes to cryptography 💀 I tend to just query chatgpt for guidance and solutions most of the time but hopefully I will be less reliant with it in the future 😭

### Mesej Rahsia

![Untitled](Attachments/Pasted%20image%2020240902173556.png)

The python file:

```python
a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z='j','b','a','c','m','n','i','p','o','q','r','t','x','z','v','s','u','y','h','g','d','e','f','k','l','w'
flag=((3108,"{",p,q,b,p,l,g,l,q,l,v,"_",d,g,h,s,v,k,"_",l,v,m,l,"}")[::-1])
```

Based on this, the flag seemed to be in reverse and we would just have to tweak it a lil bit to output the flag in the correct format:
```python
flag=((3108,"{",p,q,b,p,l,g,l,q,l,v,"_",d,g,h,s,v,k,"_",l,v,m,l,"}")[::1])
flag = ''.join(str(item) for item in flag)
print(flag)
#flag = 3108{substitute_cipher_text}
```

### Tanpa Nama 3
![Untitled](Attachments/Pasted%20image%2020240902174433.png)

The python file in this case contains a function that takes in two strings (`binary_str` and `xor_str`) and return us with the result after an XOR operation.
```python
def xor_with_binary(binary_str, xor_str):
    binaries = binary_str.split()
    xor_num = int(xor_str, 2)
    xor_results = []
    for b in binaries:
        num = int(b, 2)
        result_num = num ^ xor_num
        xor_results.append(format(result_num, '08b'))
    return ' '.join(xor_results)

binary_str = "01010110 01010100 01010101 01011101 00011110 00110110 01010100 00101000 00110101 00101001 01010110 00111010 00100110 00110111 00110101 00111100 00110001 01010101 00111010 00100110 00101101 00100100 00101001 00101001 00100000 00101011 00100010 00100000 00011000"
xor_str = "01100101"

```

![Untitled](Attachments/Pasted%20image%2020240902174702.png)

Taking the result to cyberchef gave us the flag eventually:

![Untitled](Attachments/Pasted%20image%2020240902174744.png)

### Syah Sesat
![Untitled](Attachments/Pasted%20image%2020240902174935.png)

We were given a cipher and a key.  Take the cipher and decode it with the key in _Vigenère cipher_ gave us the string `AMAL_AYADUB_SUBMAG{8013SUBMAGNAGNEDATNICHUTAJAYASINUGALRAGNEDKAJES`.
As we can see the string is reversed and reversing it eventually gave us the string with the flag in it `SEJAKDENGARLAGUNISAYAJATUHCINTADENGANGAMBUS3108{GAMBUS_BUDAYA_LAMA}`

### Kekacauan Huruf
![Untitled](Attachments/Pasted%20image%2020240902175417.png)

chal.py
```python
import random
from Crypto.Util.number import bytes_to_long, long_to_bytes

q = 64

# Read the flag from a file
flag = open("flag.txt", "rb").read()
flag_int = bytes_to_long(flag)

# Add random padding
padding_length = random.randint(5, 10)
padding = random.getrandbits(padding_length * 8)
flag_int = (flag_int << (padding_length * 8)) + padding

# Generate the secret key
secret_key = []
while flag_int:
    secret_key.append(flag_int % q)
    flag_int //= q

# Shuffle the secret key
original_order = list(range(len(secret_key)))
random.shuffle(original_order)
shuffled_secret_key = [secret_key[i] for i in original_order]

# Add a random offset to each value in the secret key
offset = random.randint(1, q)
shuffled_secret_key = [(x + offset) % q for x in shuffled_secret_key]

# Save the secret key and offset
with open("secret_key.txt", "w") as f:
    f.write(f"secret_key = {shuffled_secret_key}\n")
    f.write(f"offset = {offset}\n")
    f.write(f"padding_length = {padding_length}\n")
    f.write(f"original_order = {original_order}\n")

print("Secret key, offset, and original order saved to secret_key.txt")

```

Utilizing all of my crypto skills, I gently asked chatgpt to make a reverse script and we got an answer from it:

```python
#solve.py
from Crypto.Util.number import long_to_bytes

q = 64

# Given values from the key file
shuffled_secret_key = [54, 38, 12, 47, 37, 37, 53, 22, 6, 38, 62, 22, 10, 54, 19, 41, 43, 53, 0, 62, 63, 28, 63, 63, 22, 10, 7, 37, 63, 53, 44, 8, 10, 42, 35, 43, 42, 63, 37, 21, 4, 19, 45, 21, 19, 18, 3, 62, 53, 24, 2, 62, 18, 35, 41, 14, 53, 3, 37, 63, 55, 62, 5]
offset = 50
padding_length = 9
original_order = [9, 20, 6, 12, 22, 38, 14, 24, 53, 52, 61, 29, 45, 11, 57, 44, 8, 46, 55, 59, 31, 2, 51, 43, 21, 27, 17, 40, 15, 58, 0, 26, 19, 36, 60, 28, 48, 39, 34, 50, 7, 16, 56, 30, 10, 49, 13, 3, 5, 42, 41, 47, 37, 4, 32, 33, 62, 1, 18, 23, 25, 35, 54]

# Step 1: Reverse the offset addition
original_secret_key = [(x - offset) % q for x in shuffled_secret_key]

# Step 2: Restore the original order
restored_secret_key = [0] * len(original_secret_key)
for i, pos in enumerate(original_order):
    restored_secret_key[pos] = original_secret_key[i]

# Step 3: Reconstruct the flag integer
flag_int = 0
for x in reversed(restored_secret_key):
    flag_int = flag_int * q + x

# Step 4: Remove the padding
flag_int >>= padding_length * 8

# Step 5: Convert to bytes to get the flag
flag = long_to_bytes(flag_int)
print("Recovered flag:", flag)

```

Flag: `3108{9546880676d3788377699aad794c5a44}`

### Pandak Lam
![Untitled](Attachments/Pasted%20image%2020240902175713.png)

We were given a file with random texts (cipher) in it

![Untitled](Attachments/Pasted%20image%2020240902175811.png)

We tried to decode the cipher with ROT13 in cyberchef and we found the flag hidden among the texts
![Untitled](Attachments/Pasted%20image%2020240902175940.png)

Flag: `3108{3108k3b4ngk1tanp4hl4w4n}`

---

## Trivia and Misc 🧩
### Sembunyi
![Untitled](Attachments/Pasted%20image%2020240902180455.png)

This one took me quite a way I ain't gon lie cuz silly me thought the hidden characters were morse code for whatever reason. 

Upon opening the file in a text editor, we see nothing but nothing. 
![Untitled](Attachments/Pasted%20image%2020240902180736.png)

However, highlighting the file revealed something interesting:
![Untitled](Attachments/Pasted%20image%2020240902180824.png)

As mentioned above, I thought this was morse code initially. After some further researching, this seemed to be a whitespace encoding and apparently whitespace language is a thing. With this info, we head on to https://www.dcode.fr/whitespace-language and paste the file content to retrieve our flag:

![Untitled](Attachments/Pasted%20image%2020240902181357.png)


## Cordini
![Untitled](Attachments/Pasted%20image%2020240902181437.png)

A free flag challenge where we just had to head on towards the discord, react to a message and get rewarded.

![Untitled](Attachments/Pasted%20image%2020240902181545.png)

![Untitled](Attachments/Pasted%20image%2020240902181557.png)


Definitely could've solve more challenges that were worth 100pts under this category but oh well spent too much time on other challenges i guess.

---

## OSINT 🔍
## Jalan-Jalan Desa
![Untitled](Attachments/Pasted%20image%2020240902181936.png)

Image File:
![Untitled](Attachments/Pasted%20image%2020240902182124.png)

The challenge description stated that Syah likes to leave reviews for places she visited so that'll be the direction we'll be going for. I first did a quick google reverse search to try and find out where the location in the image is and it is the Muzium Kota Kayang

![Untitled](Attachments/Pasted%20image%2020240902182342.png)

Following our direction above, I tried to open the links where it might be a blog and search for the flag format from them one by one.  We eventually stumble upon this blog https://thriftytraveller.wordpress.com/2012/04/09/kota-kayang-museum-perlis/ and the flag is located in the comments section

![Untitled](Attachments/Pasted%20image%2020240902182725.png)

This is a tedious solution and its certainly not the most effective but oh well.

## Perigi
![Untitled](Attachments/Pasted%20image%2020240902183003.png)

For this challenge, we were given a rar file which prompts us for a password upon trying to uncompress it:

![Untitled](Attachments/Pasted%20image%2020240902183025.png)

Looking back at the challenge description, it is hinting us to find out which country poisoned the well for the second time around. A quick googling and we can find out the answer to this is `Belanda`

![Untitled](Attachments/Pasted%20image%2020240902183342.png)

Use that to extract the files and we will be given the flag: `3108{th3_k1ngs_w3ll_st4ys_0n}`

### Bawang

> [!NOTE]
> Unfortunately I couldn't access the site anymore a few days after the challenge ended so this will just be a simple walkthrough without some important screenshots. Apologies.
> Also, this challenge was also categorized as a web challenge but I think it leans more towards the OSINT side imo so there's that. 

![Untitled](Attachments/Pasted%20image%2020240902183547.png)

Bawang is onion when translated and was obvious enough that it has something to deal with onion sites with Tor. 
We paste the address `tmdjl5kyfzimrsrkkjisxybwb7664epxizxfz6hbivkg6k4a3x2svrad.onion`into the address bar and were redirected to a login form. Viewing the source code of the page gave us credentials in plaintext that we can utilize to login to the portal. 
Upon successfully logged in, we were given three Nasi Kandar places with their precise coordinates. Look for the places one by one in google review and we will find an image with the flag in it. 
Again, my bad for not taking screenshots during the challenge.


## Forensics 🕵️

### Tinggi Lagii
![Untitled](Attachments/Pasted%20image%2020240902184834.png)

We were asked to find the latitude and longtitude of the tallest building that was not built in Malaysia and an image. 
![Untitled](Attachments/Pasted%20image%2020240902184941.png)

A quick google reverse image search tells us that this is the Tradewinds Square and we can find its coordinates through Google Maps:

![Untitled](Attachments/Pasted%20image%2020240902185058.png)

Flag: `3108{3.15,101.70}`

### Pahlawan Lagenda

![Untitled](Attachments/Pasted%20image%2020240902185201.png)

We were given a text file with filler text in it 

![Untitled](Attachments/Pasted%20image%2020240902185337.png)

Again, we can filter out the flag format for the flag:
![Untitled](Attachments/Pasted%20image%2020240902185402.png)

### Kontras
![Untitled](Attachments/Pasted%20image%2020240902185506.png)

We were asked to find a key that was not redacted correctly within the given pdf file. 
We can easily search for the flag format and it was found that the flag was hidden in plain sight with white color font
![Untitled](Attachments/Pasted%20image%2020240902185837.png)

Copy the text and we'll get the flag: `3108{Peghak_Darul_ridzuAn}`

## Network 📡

### Pangkalan
![Untitled](Attachments/Pasted%20image%2020240902190010.png)

Challenge gave us a pcap file for analysis and the description told us something about port 55663. 
We can then filter the traffics on that specific port `tcp.port == 55663` and follow the TCP streams to see what's on.

![Untitled](Attachments/Pasted%20image%2020240902190249.png)

Following the streams one by one gave us pieces of a base64 encoded string. We then combine together the string and this gave us the string `Mw==MQ==MA==OA==ew==bWlrZQ==YWxwaGE=bGltYQ==YnJhdm8=YWxwaGE=dGFuZ28=dGFuZ28=fQ==`   
decoding the string gave us the flag

![Untitled](Attachments/Pasted%20image%2020240902190440.png)

except... its not.  The words in the flag looked strange and I pasted them for a Google search:

![Untitled](Attachments/Pasted%20image%2020240902190613.png)

As we can see,  it's a NATO Phonetic Alphabet and here are specific mappings for each of the words. Map the words we get the flag - `3108{MALBATT}`

---

## Web 🕸️
### Sultan yang Hilang

![Untitled](Attachments/Pasted%20image%2020240902193908.png)

Upon visiting the URL provided, we were presented with a page with a list of sultan Kelantan

![Untitled](Attachments/Pasted%20image%2020240902194049.png)

Looking at the page source we can see a script that has an endpoint that takes in values from the `sultanYears` and returns JSON data.  

![Untitled](Attachments/Pasted%20image%2020240902194135.png)

For example, visiting the endpoint with year 1763 gave us the following:

![Untitled](Attachments/Pasted%20image%2020240902194401.png)

Relating back to the question (sultan yang hilang - the missing sultan), I thought that we might be in the search for a missing sultan that is not on the list. The wikipedia page gave us a nicely detailed list of sultan Kelantan where we can find the missing piece:

![Untitled](Attachments/Pasted%20image%2020240902194611.png)

Checking the list, the missing one was Sultan Muhammand III from year 1889-1890. Looking for it in the endpoint will give us the flag:

![Untitled](Attachments/Pasted%20image%2020240902194812.png)

## Merdeka
![Untitled](Attachments/Pasted%20image%2020240902194951.png)

The url presents us with a site with some of Malaysia's patriotic songs and their lyrics.  

![Untitled](Attachments/Pasted%20image%2020240902195223.png)


Taking a look at the page source, we found that this which was the only section that was interesting and could be our attack vector. In this case, the `setPage()`  function is taking a page as its argument and encodes the page in base64 with `btoa()`.  It then sets the encoded page as a `page` cookie and proceeds to reload the page. 

At first thought, I feel that this might be vulnerable to Local File Inclusion or Remote File Inclusion attacks if the user input to the `setPage()` function is not sanitized appropriately.  

![Untitled](Attachments/Pasted%20image%2020240902195334.png)


To test our theory, we can encode the page `etc/passwd` with base64 and pass it as the value of the cookie and observe the response. 

![Untitled](Attachments/Pasted%20image%2020240902200358.png)

Indeed we have LFI!  I then tried to access `var/www/html/index.php` to view the backend code of the page but was presented with a rather different response

![Untitled](Attachments/Pasted%20image%2020240902200603.png)

It seemed like the script might have some [Memory Leak](https://stackoverflow.com/questions/561066/fatal-error-allowed-memory-size-of-134217728-bytes-exhausted) or it exceeded the maximum allocated memory size. I then make use of a php filter wrapper payload from Hacktricks in the  attempt to try and read the requested files from the server:  `php://filter/convert.base64-encode|convert.base64-decode/resource=file:///var/www/html/index.php`

With this, we successfully retrieved the `index.php` file for the site.
![Untitled](Attachments/Pasted%20image%2020240902202512.png)

Decoding from cyberchef:

![Untitled](Attachments/Pasted%20image%2020240902202648.png)

The flag was nowhere to be seen in the `index.php` file and there were nothing interesting in it. I tried to find the flag at common locations like `/root/root.txt` but the flag was found in the `/var/www/html/config.php` file in the end.

![Untitled](Attachments/Pasted%20image%2020240902203004.png)


## Kapla Harimau Selatan

![Untitled](Attachments/Pasted%20image%2020240902204939.png)

The challenge description stated something about a hidden key in plain sight so that might be useful for us moving forward (spoiler - its not).

We were presented with this page after visiting the URL:

![Untitled](Attachments/Pasted%20image%2020240902205911.png)

At this point, I have completely zero idea as to where do we go from here as we were not allowed to fuzz directories or anything of that like. The page source didn't have anything interesting, `robots.txt` was not found, and no cookies were set too. 

After sometime, the organizers planned to release a hint at the page source:

![Untitled](Attachments/Pasted%20image%2020240902210104.png)

Visiting that page presented us with what it seemed like its the logic for the site:

```php
<?php

header("Access-Control-Allow-Origin: https://127.0.0.1");

$headerName = 'Origin';
$headerValue = 'https://127.0.0.1';
$secondaryHeaderName = 'X-Custom-Header';
$secondaryHeaderValue = 'Sm9ob3IganVnYSBkaWtlbmFsaSBzZWJhZ2FpIEdfX19fX19fIG9sZWggb3JhbmcgU2lhbQ==';

$headerKey = 'HTTP_' . strtoupper(str_replace('-', '_', $headerName));
$secondaryHeaderKey = 'HTTP_' . strtoupper(str_replace('-', '_', $secondaryHeaderName));

if (isset($_SERVER[$headerKey]) && isset($_SERVER[$secondaryHeaderKey])) {
    $actualValue = $_SERVER[$headerKey];
    $actualSecondaryValue = $_SERVER[$secondaryHeaderKey];

    if ($actualValue === $headerValue && $actualSecondaryValue === $secondaryHeaderValue) {
        echo "The flag is 3108{this-is-fake-flag}";
    } else {
        echo "Close enough";
    }
} else {
    echo "Denied!";
}

?>
```

Based on the code, the condition was checking if the `$headerValue` that is controlled by us is same as the `$actualValue` in the server and if the `$secondaryHeaderValue` that we have control is same as the `$actualSecondaryValue` from the backend. If these conditions are passed, we get the flag, simple as that. 

For the `$headerValue`, we can see that it is holding the string `https://127.0.0.1` which is a loopback address and with this I had no idea what the `$actualValue` from the backend was supposed to be. 

We also noticed that the `$secondaryHeaderValue` variable is holding a base64 encoded string which decodes to `Johor juga dikenali sebagai G_______ oleh orang Siam`. That looks like a hint where will need to find an answer to fill in the blank and that can be done quickly through a simple Google search:

![Untitled](Attachments/Pasted%20image%2020240902210555.png)

With our info gathered, I tried to manipulate the request headers as such:

![Untitled](Attachments/Pasted%20image%2020240902211018.png)

where I used the header `Origin: https://127.0.0.1` with the same value provided above ('https://127.0.0.1') and the header `X-Custom-Header` with the base64 encoded string of 'Gangganu' to match with the above logic code. I then got this in response :

![Untitled](Attachments/Pasted%20image%2020240902211207.png)

Close enough. Hmm....  I then tried again with the plaintext 'Gangganu' andddd we got the flag!

![Untitled](Attachments/Pasted%20image%2020240902211250.png)


### Hang Tak Tidur Lagi?

![Untitled](Attachments/Pasted%20image%2020240902211529.png)

We were presented with a login form upon visiting the URL:

![Untitled](Attachments/Pasted%20image%2020240902211830.png)

Common credentials `admin:admin admin:password` didn't work so we took a look at the page source. 
Interesting enough, the source code had a comment with credentials for the login portal:

![Untitled](Attachments/Pasted%20image%2020240902211947.png)

Upon logging in, we were presented with a message stating that we don't have access to the flag with the word 'Laksamana' being bolded out.  

![Untitled](Attachments/Pasted%20image%2020240902212030.png)

Nothing much from the source code here and I decided to take a look at the cookies if there are any

![Untitled](Attachments/Pasted%20image%2020240902212159.png)

As we can see, we have a `role` cookie which is clearly custom to the target application. I then tried to test if we can decode the cookie value to get more information and indeed we can:

![Untitled](Attachments/Pasted%20image%2020240902212347.png)

It is a base32 encoded value of the word 'LAKSAMANA'. At this point, I'm thinking that we might need to manipulate this value by using different roles such as 'sultan' or any high privileged users that might grant us access. 

Unfortunately, that didn't work. Looking back at the description we can see that the word 'Pembesar Berempat' was bolded too. Hang Tuah, the main character of this challenge is part of the 'Pembesar Berempat' and he was a Laksamana. A quick read about the 'Sistem Pembesar Empat Lipatan' tells us that there are four other roles in the system.

![Untitled](Attachments/Pasted%20image%2020240902212916.png)

I then tried to encode 'BENDAHARA' with base32 and send that as the cookie `role` and we got a different response in return:

![Untitled](Attachments/Pasted%20image%2020240902213056.png)

We got the first part of the flag, indicating we're on the right track. Repeating the process with 'Penghulu Bendahari' and 'Temenggung' gave us the full flag. 

Flag: `3108{1d0R_s4nGa7l4h_Bah4y4!}`

### Wordle Bahasa Utaqa
![Untitled](Attachments/Pasted%20image%2020240902213252.png)

This is a simple challenge with a malay wordle that we would have to play in order to obtain the flag. Thus, I will not be showcasing it.

Flag: `3108{h4ng_m3m4ng_s3mp0i}`











