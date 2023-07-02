<h1>picoCTF 2023 Writeup</h1>

<h2>Table of Contents</h2>

* [Binary Exploitation Challenges](#binary-exploitation-challenges)
   * [Challenge: two-sum](#challenge-two-sum)
   * [Challenge: VNE](#challenge-vne)
   * [Challenge: hijacking](#challenge-hijacking)
   * [Challenge: HideToSee](#challenge-hidetosee)
   * [Challenge: ReadMyCert](#challenge-readmycert)
   * [Challenge: rotation](#challenge-rotation)
* [Forensics](#forensics)
   * [Challenge: hideme](#challenge-hideme)
* [Web Exploitation](#web-exploitation)
   * [Challenge: findme](#challenge-findme)
   * [Challenge: MoreSQLi](#challenge-moresqli)


![a8ddf567_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/4c97242a-f7b8-45d9-bb6c-80e1d4104d84)

Unfortunately, the following write-up that I have created does not consist of a write-up for every single challenge that I had done but it does consist of a large majority of challenges. Also, this does not include any write-ups for the General Skills challenges.

# <u>Binary Exploitation Challenges</u>

## <u>Challenge: two-sum</u>

The challenge below involves a file which is vulnerable to an integer overflow. When an integer overflow is caused and the necessary conditions are met to solve the challenge the program will display the flag. An integer overflow occurs when an arithmetic operation attempts to create a numeric value which is beyond the number of digits which is used to represent it. The reason I was able to deduce that it is an integer overflow comes from the hints which suggest that it’s not a traditional math problem and more so an issue with the program.

![a2942fce_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/4ace674e-dfd7-4d46-ab43-12919d8b39d8)

<br/>

This challenge provides the source code, so I started by downloading and opening it to understand how the program functions. 

![c0d022df_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/79d1fb5d-d4d9-4493-a78e-e2009455ebbb)


```c
#include <stdio.h>
#include <stdlib.h>

static int addIntOvf(int result, int a, int b) {
    result = a + b;
    if(a > 0 && b > 0 && result < 0)
        return -1;
    if(a < 0 && b < 0 && result > 0)
        return -1;
    return 0;
}

int main() {
    int num1, num2, sum;
    FILE *flag;
    char c;

    printf("n1 > n1 + n2 OR n2 > n1 + n2 \n");
    fflush(stdout);
    printf("What two positive numbers can make this possible: \n");
    fflush(stdout);
    
    if (scanf("%d", &num1) && scanf("%d", &num2)) {
        printf("You entered %d and %d\n", num1, num2);
        fflush(stdout);
        sum = num1 + num2;
        printf("Value of sum is %d", sum);
        if (addIntOvf(sum, num1, num2) == 0) {
            printf("No overflow\n");
            fflush(stdout);
            exit(0);
        } else if (addIntOvf(sum, num1, num2) == -1) {
            printf("You have an integer overflow\n");
            fflush(stdout);
        }

        if (num1 > 0 || num2 > 0) {
            flag = fopen("flag.txt","r");
            if(flag == NULL){
                printf("flag not found: please run this on the server\n");
                fflush(stdout);
                exit(0);
            }
            char buf[60];
            fgets(buf, 59, flag);
            printf("YOUR FLAG IS: %s\n", buf);
            fflush(stdout);
            exit(0);
        }
    }
    return 0;
}
```

Based on the source code, the program prompts the user to input two numbers. The two numbers will be added together and meet the condition whereby both numbers are either smaller or larger than the result. If either condition is met, it will essentially print out the flag. 

<br/>

**Summary of Conditions to Meet:**

- `num1 > num1 + num2`  OR `num2 > num1 + num2`

- ( `num1 > 0`  AND `num2 > 0` AND `result < 0` ) OR ( `num1 > 0`  AND `num2 > 0` AND `result < 0` )

<br/>

Mathematically, however, it would not be possible to meet those conditions. Hence, we would need to rely on another method which is an integer overflow in this case. As mentioned before an integer overflow occurs when the number in the result of the operation is more than the number of bits allowed within the system. In a typical 32-bit system, there is a maximum integer range from **0** to **4294967295**.

![e3149cf8_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7334680b-4a79-41f1-b0a2-a03b40b728a5)

<br/>

Another thing to note for these types of challenges is whether it uses signed or unsigned integers. Unsigned integers only involve positive numbers and fall into the maximum integer range mentioned before. However, this challenge involves signed integers, hence, the integer range, in this case, is between **-2147483648 **and **2147483647. **

<br/>

Therefore, in order to cause an integer overflow with both the numbers added together I used the numbers **2147483647 **and added it by **1 **to cause an integer overflow which caused the sum to be **-2147483648. **This is proven when connecting to the server via `netcat` and inputting the two numbers mentioned, thus, giving me the flag.

![cc5b056d_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/54ea844d-4ad2-4147-b4b5-4d600ccc4159)

<br/>

**Flag: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_ccd078bd}**

<br/>

## <u>Challenge: VNE</u>

This challenge involves the exploitation of a binary file by injecting commands into the environment variable so that it executes our arbitrary commands. An environment variable is commonly used by Linux programs and scripts to store and retrieve information related to the operating system environment such as paths, user names, default shell and more. Some of the main hints are provided in the challenge tags and the title of the challenge which is “ENV” backwards.

![5cf8576c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/c1ac9077-3ed3-417b-924d-800eac873992)

<br/>

This challenge provides the SSH (Secure Socket Shell) credentials that allowed me to connect to the remote server. Command to connect to the server `ssh -p [PORT_NUMBER] ctf-player@saturn.picoctf.net` along with the password `8a707622`. 

![0ffbc4fc_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/9e3c86f2-a298-4529-a445-39921ba310bf)

<br/>

Upon connecting to the server via SSH. I found the 64-bit binary file named `bin` within the home directory of the user. Additionally, the file is owned by the **root **user.

![c1bf45a8_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/2572eac9-4144-4665-a4fc-b18562c6e00c)

<br/>

When trying to execute the file, it displayed an error message stating that one of the environment variables were not set. 

![438f9998_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/3ba3b263-4aad-4e66-bde0-c4397c9a0843)

<br/>

Looking at the environment variables via the command `env` I wasn’t able to find any environment variables named** “SECRET_DIR”**. 

![0c1becf1_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/306c87b9-4af6-40d9-b367-82934be20635)

<br/>

As the program required the** “SECRET_DIR”** environment variable, I decided to set the variable and inject my own **bash **commands within the variable. The command I used was `export SECRET_DIR="ls /challenge"`. I then verified if my environment variable was set using `env` once again.

![d01d0215_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/67ce66aa-8dd5-4a67-ae4a-f7bdef49943d)

<br/>

With that, I ran the `bin` binary again to see if the bash command injected into the environment variable would actually work. It was able to show me a `flag.txt` file within the `/root` directory. 

![c35b2922_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/bbeab826-883e-4e23-a16a-bb14df5b88f1)

I then added an extra command in the environment variable so that it would also read out the contents of the file named `flag.txt`. The command used was `export SECRET_DIR='/root && cat /root/flag.txt'` . With that, I executed the file and was provided with the flag.

![09eb0179_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/83ada392-de53-4bd4-8d04-a833d0e83326)

<br/>

**Flag: picoCTF{Power_t0_man!pul4t3_3nv_3f693329}**

## <u>Challenge: hijacking</u>

The main hints for this comes from the tags which point to a **privilege escalation** which is a term for obtaining higher privileges for hosts we have access to. Another hint is located within the challenge description which points out that there is a Python file within the server that can be exploited to obtain higher-level privilege. The other 2 hints provided in the challenge just show where the hidden Python file can be found.

![a0671168_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/d254700c-1ceb-46b9-a36a-6b023ffd9284)

<br/>

For this challenge, I first connected, to the server via SSH using the credentials provided. SSH command: `ssh -p [PORT_NUMBER] picoctf@saturn.picoctf.net`

![ba47fb76_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/582ef189-a471-41ce-9712-9599100b10ac)

<br/>

First, I searched for the Python file which I found was located in the directory `/home/picoctf`. It was a hidden file within the directory which we can use `ls -al`. The name of the file was `.server.py` which was owned by the **root** user.

![78664422_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/8ef1a208-c246-48b8-b6b5-9c3b9c9a01c8)

<br/>

Taking a further look at the Python file using the `cat` command, I was able to read the source code of the file which was essentially to ping a host and gather information about the host.

![d1b7318b_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/5e2fc69c-47c0-444b-b583-86f38a762b97)

Something important to note is that the source code involved the use of some Python libraries. This could be used to my advantage by changing the contents of the libraries to instead execute my code. 

<br/>

Running `sudo -l`  in the terminal shows us that we are able to execute certain commands as **root. **One of those commands is `/usr/bin/vi` (vim → text editor) which can be run by all users. Hence, we can use this to edit the files despite being owned by the root user. Another command we have access to is also to run the `.server.py` file as root without requiring a password. 

![5220f11a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/4f316ce4-b858-484c-8d13-c597f3dec402)

<br/>

With this information, I realised that I needed to hijack one of the Python libraries that were imported in the `.server.py` file with my own code to escalate to **root privilege.** Hence, I made a new `base64.py` file to which I put my own code into so that the Python file would instead import the contents of my file instead of the actual base64 python library. 

![f5077a54_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7a128e0e-778f-4729-9e17-8bc15bf516d6)

<br/>

The code that I used involved the `os` library so I can spawn a bash shell. If the program were to be run with `sudo` it should spawn a shell as **root.**

![3f7c966a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/2844ddb9-04b6-4c67-b74c-8c64a62083f8)

![48e51ebd_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/c8207e27-c6a2-4b7e-bb48-ab57ca61dbc0)

After creating the new `base64.py`, I then ran the `.server.py` file using the command `sudo /usr/bin/python3 /home/picoctf/.server.py`  which spawned a root shell.

![20fc1132_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/702fee53-8d08-4474-8dfb-13f3f863e6fc)

<br/>

With this, I was able to obtain **root** privileges and was able to navigate to the `/challenge` directory and found a file named `metadata.json` which contained the flag. 

![2c3d4138_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/3a869ba6-54c3-4182-a509-209d2ee25e7c)

<br/>

**Flag: picoCTF{pYth0nn_libraryH!j@CK!n9_f56dbed6}**

<br/>

## <u>Challenge: HideToSee</u>

This is a very simple challenge that involves image steganography. Steganography is the practice of hiding messages or information within files such as audio and image files (basically not displaying the text). The information or data can be obtained by extracting the contents from the file itself. One of the main hints of this challenge is provided, which is i to download and extract the contents from the image.

![1acb85eb_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/d62fcc8c-471e-4275-8bfc-428513319524)

<br/>

Firstly I started by downloading the image file from the challenge description and observing it. The image essentially showed what the Atbash cypher looked like. 

![92f01c8c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/1182ce50-6671-4171-8b8a-d0935db07862)

![f10b6a0a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/9a16b9f4-bf4b-45f1-8e7b-0ebc815f1920)

<br/>

Next, I opened up the terminal and used steghide to see if there was anything hidden within the `atbash.jpg` image file. The command used is `steghide --info atbash.jpg`. 

![bc7920e7_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/625d0133-9e9b-4aa3-893a-10ce9be25495)

In this case, the image did not require a passphrase to view the contents which made it even easier. As seen in the image above, the image file contains a file within it called **encrypted.txt.**

<br/>

With this knowledge, I then used **steghide** once again to extract the contents hidden within the image file using the command `steghide extract -sf atbash.jpg` without a passphrase.

![a601739d_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/ade1a871-f000-4809-8aef-647e3709c16a)

![2e6ff67c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a9ff0b8e-7a78-42b9-9f90-7bdf8429c171)

<br/>

I then checked the contents of the **encrypted.txt **file and found something that looked similar to a flag. 

![9e7dbf48_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a13ff4dd-ee24-4c28-88af-24e9a78b14a9)

<br/>

I then remembered another hint which was the Atbash cipher in the image from before. So I instictively tried to decipher it using **[CyberChef](https://gchq.github.io/CyberChef/#recipe=Atbash_Cipher()&input=a3J4bFhHVXt6Z3l6aHNfeGl6eHBfencyMXl4Mnh9)****. **With this, I was able to obtain the flag and solve the challenge.

![d638e0da_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/8b955147-dd34-4559-91f9-40f1e327d0bf)

<br/>

**Flag: picoCTF{atbash_crack_ad21bc2c}**

<br/>

## <u>Challenge: ReadMyCert</u>

The challenge below uses a CSR (Certificate Signing Request) file which is one normally one of the first steps when trying to get an SSL/TLS certificate. This challenge provides us with a CSR file in hopes of trying to decipher it and find the flag. 

![8c29dceb_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/c1c14e51-0658-4c2e-81a4-9d28cf7c9c99)

<br/>

For this challenge, I first downloaded the file provided in the challenge  and used the `cat` command to view the contents of the file. 

![e593be6a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/8fb27240-9697-44aa-860f-b1858e960e3e)

<br/>

As it was a certificate request, I used  `openssl`  which is a command line tool used to generate private keys, create CSRs, install SSL/TLS certificates and even identify information about certificates. The command I used is  `openssl req -in readmycert.csr -noout - text`  to decipher the contents of the **readmycert.csr** file.

<br/>

**Command Breakdown:**

`req` → Specifies that the file is a CSR file

`-in` → Specifies the input for the file which is **readmycert.csr**

`-noout` → Ensures that openssl does not output any information to the terminal or the file

`-text`  → For the output of the CSR file to be in a textual and human-readable format

<br/>

![2ef9f08e_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/bf9a4652-8855-4e47-85bb-716cdd868a8c)

Within the deciphered CSR file, we are able to find the flag.

<br/>

**Flag: picoCTF{read_mycert_cda8cb26}**

<br/>

## <u>Challenge: rotation</u>

This is also another Cryptography challenge involving the shifting of characters hence the name “rotation”. 

![04e91167_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/f4acb140-533d-444f-b822-e418833d52d1)

<br/>

I started by first downloading the file **encrypted.txt **which was provided in the challenge and viewed its contents using the `cat` command. 

![c95c9251_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/dbd905cc-a92d-42b9-ba77-2f3ce574993f)

The text within the file seemed to resemble the flag however the characters were shifted which brought up the possibility that it could be a ROT-13 or Caesar Cipher. 

<br/>

Hence, I opened up CyberChef and checked if it was a ROT-13 cypher which is a forward shift of 13 characters.

![b3433456_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/1080f2a9-fd19-4f08-97ca-e721c37f5c08)

<br/>

Since that wasn’t the case, I attempted to change the number of characters it was shifted by to hopefully find the flag. Eventually, I stumbled upon it by increasing the number of shifted characters to 18 which revealed the flag. 

![8947cdd8_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/0eed431c-2e99-42a5-979f-4d7dc837f69d)

**Flag: picoCTF{r0tat1on_d3crypt3d_bdf2f252}**

<br/>

# <u>Forensics</u>

## <u>Challenge: hideme</u>

This is a simple challenge involving the use of image steganography. The main hints of this challenge are found within the tags and description of the challenge itself. 

![d8b27260_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/93d06e89-823e-47a5-ac1e-9dcffe6c241d)

<br/>

For this challenge, I first started by downloading the image provided in the challenge description. The name of the file was `flag.png` and it was the PicoCTF logo. 

![4cd20f94_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/5ab232a8-a2c1-492d-8acf-9e0387ab63bc)

<br/>

I then used `binwalk` which is a popular tool used to analyze and extract information from image files. Firstly, I used the command `binwalk flag.png`  to identify if there were any files contained within this file and sure enough there were hidden zipped files within it.

![351fc577_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/9b11eaae-6138-4501-be3c-7b5d9353ea0f)

<br/>

Next, I used the command `binwalk --extract flag.png` to extract the contents hidden within the image file.

![a4eada13_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/ec96e247-af76-484d-8414-f867f85ad9ef)

<br/>

Inside the extracted folder, I found a directory named **secret** which I had looked into.

![652f7e19_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/0656d726-0241-4ba9-a225-9a6150df7668)

<br/>

Inside this directory contained an image file which is also named **flag.png. **Opening up the image file I found the flag. 

![32d4bf0b_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/33e655bf-d4a4-4d45-9497-32b34dfe8e5a)

<br/>

**Flag: picoCTF{Hiddinng_An_imag3_within_@n_ima9e_ad9f6587}**

<br/>

# <u>Web Exploitation</u>

## <u>Challenge: findme</u>

![0ae17374_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/49a58f92-281f-4f9e-98d0-5179b203a7d9)

<br/>

For this challenge, I first went to the website and checked its contents. It appeared to be a standard login page.

![e29faeb7_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/e3455598-0753-4e16-aa27-5d227d4e2a91)

<br/>

I also checked the page source to see if there was anything sketchy. However, I couldn’t find anything that looked out of place.

![34f8fe89_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/4139af23-c483-47c0-a941-12a0434ea5c2)

<br/>

Next, I tried to log in with the credentials provided in the challenge description which worked accordingly.

![f3972752_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/1587c202-891b-43c7-9269-f2fbe80256e6)

<br/>

Upon logging in, I was redirected to another page. The page had a search box with a message asking to search for flags which could possibly hint at an injection attack.

![31e1b249_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/0371975c-cf00-408a-acbe-a88e089a317e)

<br/>

I tried viewing the page source first to find any useful information, however, there was nothing out of the ordinary. 

![12fff07c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/c775ff26-5600-46d6-82b4-32146103d6dd)

<br/>

I then tried various different injections to see if they worked but none of them seemed to work. I then returned back to the login page to see if I missed anything. After looking through everything, I was still unable to find a hint, so I tried logging in again.

![ef0bb6b6_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/bc72ac95-caae-492f-9e42-ed87c8d730f9)

<br/>

It was then I noticed something odd on the login page after that. I noticed the URL bar had two different redirections prior to reaching the `/home` directory on the website. If the redirections are too quick when trying to copy and paste them, I would suggest screen recording and typing them out manually.

![3580d7ed_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/09484891-c57d-4905-8bb1-38e0043bf938)

![9290aed2_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/b6f109c1-3c24-46bb-a32d-0fa1325da902)

<br/>

Taking a closer look at the URLs during the redirection process, I noticed that they looked like Base64 encodings. I then copied them quickly during the redirection process, combined them and put them into CyberChef’s Base64 decoder. After decoding it, I was able to obtain the flag.

![592b530b_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/57c835ed-eacc-4cd9-945c-e553e3f079ca)

**Flag: picoCTF{proxies_all_the_way_25bbae9a}**

<br/>

## <u>Challenge: MoreSQLi</u>

![ccec499c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/b24ec00b-ee61-4908-adf7-2b5b423fac1b)

This challenge is essentially a typical login bypass SQL injection challenge with a slight twist.

<br/>

![cf2ad049_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/4b9e4b73-cef8-45dd-b455-0cb0c1067c1f)

The image above shows what looks to be a login page on the challenge website. 

<br/>

![593a2c41_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/2968e978-b3a0-4906-b060-9e4f2acaa6a3)

When testing with basic credentials such as the username “admin” and the password “admin” an SQL error message is displayed which is a security issue. In this case, it even displays the order in which the user credentials are checked. More information on this is below.

<br/>

![9cfde4d6_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/5cf67b22-685c-4300-a337-2bcf4de2bdb5)

![91b30ae6_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a6f5bcf4-41a1-4041-83ee-46ebbc930a68)

In order to better test this, I used Burp Suite to intercept the requests with some random credentials.

<br/>

<br/>

![32818fb7_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/b62acea4-9925-4112-86d7-f7612c9a8338)

The request is then sent to the repeater to do further testing.

<br/>

<br/>

![15f10c8a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/c6039078-7854-4f3e-9a18-37ee1c1b424b)

I then tried to perform a basic SQL Injection attack to bypass the login page. In this case, the query is injected within the `username` parameter whereby the full query is ** **`**' or 1=1--**`**. **The query essentially makes the query true as `1=1` and comments out the password which allows us to log in as the first valid user (usually admin account). However, the injection failed as seen in the HTTP response.

<br/>

![37c2fb11_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/8aebffb9-62db-491f-8dfc-8c06a2722407)

I then remembered that the SQL query used on the server for the login page checks for the password first before the username. Hence, this meant that the SQL query needs to be injected within the password parameter instead.

<br/>

<br/>

![0a8b8b92_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/07d6209c-2686-47f2-9909-334ea0f3ff30)

Therefore, I switched the order of the request parameters and sent a request which worked and provided the flag.

<br/>

**Flag: picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_c8ee9477}**

<br/>

<br/>

<br/>

