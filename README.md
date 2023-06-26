<br/>
<h1>PicoCTF 2023 Writeup</h1>

![Untitled](a8ddf567_Untitled.png)

Unfortunately, the following write-up that I have created does not consist of a write-up for every single challenge that I had done but it does consist of a large majority of challenges. Also, this does not include any write ups for the General Skills challenges.

# <u>Binary Exploitation Challenges</u>

## <u>Challenge: two-sum</u>

The challenge below involves a file which is vulnerable to an integer overflow. When an integer overflow is caused and the necessary conditions are met to solve the challenge the program will display the flag. An integer overflow occurs when an arithmetic operation attempts to create a numeric value which is beyond the the number of digits which is used to represent it. The reason I was able to deduce that it is an integer overflow comes from the hints which suggest that it’s not a traditional math problem and more so an issue with the program.

![Untitled](a2942fce_Untitled.png)

<br/>

This challenge provides the source code, so I started by downloading that and opening it to understand how the program functions. 

![Untitled](c0d022df_Untitled.png)


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

Based on the source code, the program prompts the user to input two numbers. The two numbers will be added to together and meet the condition whereby both numbers are either smaller or larger than the result. If either of the conditions are met, it will essentially print out the flag. 

<br/>

**Summary of Conditions to Meet:**

- `num1 > num1 + num2`  OR `num2 > num1 + num2`

- ( `num1 > 0`  AND `num2 > 0` AND `result < 0` ) OR ( `num1 > 0`  AND `num2 > 0` AND `result < 0` )

<br/>

Mathematically however, it would not be possible to meet those conditions. Hence, we would need to rely on another method which is an integer overflow in thise case. As mentioned before an integer overflow occurs when the number in the result in the operation is more than the number of bits allowed within the system. In a typical 32-bit sytem, there is a maximum integer range is from **0 **to **4294967295**.

![Untitled](e3149cf8_Untitled.png)

<br/>

Another thing to note for these types of challenges is whether it uses signed or unsigned integers. Unsigned integers only involve positive numbers and fall into the maximum integer range mentioned before. However, this challenge involves signed integers, hence, the integer range in this case is between **-2147483648 **and **2147483647. **

<br/>

Therefore, in order to cause an integer overflow with both the numbers added together I used the numbers **2147483647 **and added it by **1 **to cause an integer overflow which caused the sum to be **-2147483648. **This is proven when connecting to the server via `netcat` and inputting the two numbers mentioned, thus, giving me the flag.

![Untitled](cc5b056d_Untitled.png)

<br/>

**Flag: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_ccd078bd}**

<br/>

## <u>Challenge: VNE</u>

This challenge involves the exploitation of a binary file by injecting commands into the environment variable so that it executes our arbitrary commands. An environment variable is commonly used by Linux programs and scripts to store and retrieve information related to the operating system environment such as paths, user names, default shell and more. Some of the main hints are provided in the challenge tags and the title of the challenge which is “ENV” backwards.

![Untitled](5cf8576c_Untitled.png)

<br/>

This challenge provides the SSH (Secure Socket Shell) credentials that allowed me to connect to the remote server. Command to connect to the server `ssh -p [PORT_NUMBER] ctf-player@saturn.picoctf.net` along with the password `8a707622`. 

![Untitled](0ffbc4fc_Untitled.png)

<br/>

Upon connecting to the server via SSH. I found the 64-bit binary file named `bin` within the home directory of the user. Additionally, the file is owned by the **root **user.

![Untitled](c1bf45a8_Untitled.png)

<br/>

When trying to execute the file, it displayed an error message stating that one of the environment variables were not set. 

![Untitled](438f9998_Untitled.png)

<br/>

Looking at the environment variables via the command `env` I wasn’t able to find any environment variables named** “SECRET_DIR”**. 

![Untitled](0c1becf1_Untitled.png)

<br/>

As the program required the** “SECRET_DIR”** environment variable, I decided to set the variable and inject my own **bash **commands within the variable. The command I used was `export SECRET_DIR="ls /challenge"` . I then verified if my environment variable was set using `env` once again.

![Untitled](d01d0215_Untitled.png)

<br/>

With that, I ran the `bin` binary again to see if the bash command injected into the environment variable would actually work. It was able to show me a `flag.txt` file within the `/root` directory. 

![Untitled](c35b2922_Untitled.png)

I then added an extra command in the environment variable so that it would also read out the contents of the file named `flag.txt`. The command used was `export SECRET_DIR='/root && cat /root/flag.txt'` . With that, I executed the file and was provided with the flag.

![Untitled](09eb0179_Untitled.png)

<br/>

**Flag: picoCTF{Power_t0_man!pul4t3_3nv_3f693329}**

## <u>Challenge: hijacking</u>

The main hints for this comes from the tags which point to a **privilege escalation** which is a term for obtaining higher privileges for host we have access to. Another hint is located within the challenge description which points out that there is a Python file within the server that can be exploited to obtain higher level privilege. The other 2 hints provided in the challenge just shows where the hidden Python file can be found.

![Untitled](a0671168_Untitled.png)

<br/>

For this challenge I first connected, to the server via SSH using the credentials provided. SSH command: `ssh -p [PORT_NUMBER] picoctf@saturn.picoctf.net`

![Untitled](ba47fb76_Untitled.png)

<br/>

First, I searched for the Python file which I found was located in the directory `/home/picoctf` . It was a hidden file within the directory which we can use `ls -al` . The name of the file was `.server.py` which was owned by the **root** user.

![Untitled](78664422_Untitled.png)

<br/>

Taking a further look at the Python file using the `cat` command, I was able to read the source code of the file which was essentially to ping a host and gather information about the host.

![Untitled](d1b7318b_Untitled.png)

Something important to note is that the source code involved the use of some python libraries. This could be used to my advantage by changing the contents of the libraries to instead execute my code. 

<br/>

Running `sudo -l`  in the terminal shows us that we are able to execute certain commands as **root. **One of those commands is `/usr/bin/vi` (vim → text editor) which can be run by all users. Hence, we can use this to edit the files despite being owned by the root user. Another command we have access to is also to run the `.server.py` file as root without requiring a password. 

![Untitled](5220f11a_Untitled.png)

<br/>

With this information, I realised that I needed to hijack one of the Python libraries that were imported in the `.server.py` file with my own code to escalate to **root privilege.** Hence, I made a new `base64.py` file to which I put my own code into so that the Python file would instead import the contents of my file instead of the actual base64 python library. 

![Untitled](f5077a54_Untitled.png)

<br/>

The code that I used involved the `os` library so I can spawn a bash shell. If the program were to be ran with `sudo` it should spawn a shell as **root.**

![Untitled](3f7c966a_Untitled.png)

![Untitled](48e51ebd_Untitled.png)

After creating the new `base64.py` , I then ran the `.server.py` file using the command `sudo /usr/bin/python3 /home/picoctf/.server.py`  which spawned a root shell.

![Untitled](20fc1132_Untitled.png)

<br/>

With this, I was able obtain **root** privileges and was able to navigate to the `/challenge` directory and found a file named `metadata.json` which contained the flag. 

![Untitled](2c3d4138_Untitled.png)

<br/>

**Flag: picoCTF{pYth0nn_libraryH!j@CK!n9_f56dbed6}**

<br/>

## <u>Challenge: HideToSee</u>

This is a very simple challenge that involves image steganogrpahy. Steganogrpahy is the practice of hiding messages or information within files such as audio and image files (basically not displaying the text). The information or data can be obtained by extracting the contents from the file itself. One of the main hints of this challenge is provided, which is i to download and extract the contents from the image.

![Untitled](1acb85eb_Untitled.png)

<br/>

Firstly I started by downloading the image file from the challenge description and observed it. The image essentially showed what the atbash cipher looked like. 

![Untitled](92f01c8c_Untitled.png)

![Untitled](f10b6a0a_Untitled.png)

<br/>

Next, I opened up the terminal and used steghide to see if there was anything hidden within the `atbash.jpg` image file. The command used is `steghide --info atbash.jpg` . 

![Untitled](bc7920e7_Untitled.png)

In this case, the image did not require a passphrase to view the contents which made it even easier. As seen in the image above, the image file contains a file within it called **encrypted.txt.**

<br/>

With this knowledge, I then used **steghide** once again to extract the contents hidden within the image file using the command `steghide extract -sf atbash.jpg` without a passphrase.

![Untitled](a601739d_Untitled.png)

![Untitled](2e6ff67c_Untitled.png)

<br/>

I then checked the contents of the **encrypted.txt **file and found something that looked similar to a flag. 

![Untitled](9e7dbf48_Untitled.png)

<br/>

I then remembered another hint which was the Atbash cipher in the image from before. So I instictively tried to decipher it using **[CyberChef](https://gchq.github.io/CyberChef/#recipe=Atbash_Cipher()&input=a3J4bFhHVXt6Z3l6aHNfeGl6eHBfencyMXl4Mnh9)****. **With this, I was able to obtain the flag and solve the challenge.

![Untitled](d638e0da_Untitled.png)

<br/>

**Flag: picoCTF{atbash_crack_ad21bc2c}**

<br/>

## <u>Challenge: ReadMyCert</u>

The challenge below uses a CSR (Certificate Signing Request) file which is one normally one of the first steps when trying to get an SSL/TLS certificate. This challenge provides us with a CSR file in hopes of trying to decipher it and find the flag. 

![Untitled](8c29dceb_Untitled.png)

<br/>

For this challenge, I first downloaded the file provided in the challenge  and used the `cat` command to view the contents of the the file. 

![Untitled](e593be6a_Untitled.png)

<br/>

As it was a certificate request, I had used  `openssl`  which is a command line tool used to generate private keys, create CSRs, install SSL/TLS certificates and even identify information about certificates. The command I used is  `openssl req -in readmycert.csr -noout - text`  to decipher the contents of the **readmycert.csr** file.

<br/>

**Command Breakdown:**

`req` → Specifies that the file is a CSR file

`-in` → Specifies the input for the file which is **readmycert.csr**

`-noout` → Ensures that openssl does not output any information to the terminal or the file

`-text`  → For the output of the CSR file to be in a textual and human-readable format

<br/>

![Untitled](2ef9f08e_Untitled.png)

Within the deciphered CSR file, we are able to find the flag.

<br/>

**Flag: picoCTF{read_mycert_cda8cb26}**

<br/>

## <u>Challenge: rotation</u>

This is also another Cryptography challenge involving a shifting of characters hence the name “rotation”. 

![Untitled](04e91167_Untitled.png)

<br/>

I started by first downloading the file **encrypted.txt **which was provided in the challenge and viewed it’s contents using the `cat` command. 

![Untitled](c95c9251_Untitled.png)

The text within the file seemed to resemble the flag however the characters were shifted which brought up the possibility that it could be a ROT-13 or Caesar Cipher. 

<br/>

Hence, I opened up CyberChef and checked if it was a ROT-13 cipher which is a forward shift of 13 characters.

![Untitled](b3433456_Untitled.png)

<br/>

Since that wasn’t the case, I attempted to change the number of characters it was shifted by to hopefully find the flag. Eventually, I stumbled upon it by increasing the number of shifted characters to 18 which revealed the flag. 

![Untitled](8947cdd8_Untitled.png)

**Flag: picoCTF{r0tat1on_d3crypt3d_bdf2f252}**

<br/>

# <u>Forensics</u>

## <u>Challenge: hideme</u>

This is a simple challenge involving the use of image steganography. The main hints of this challenge are found within the tags and description of the challenge itself. 

![Untitled](d8b27260_Untitled.png)

<br/>

For this challenge, I first started by downloading the image provided in the challenge description. The name of the file was `flag.png` and it was the PicoCTF logo. 

![Untitled](4cd20f94_Untitled.png)

<br/>

I then used `binwalk` which is a popular tool used to analyze and extract information from image files. Firstly, I used the command `binwalk flag.png`  to identify if there were any files contained within this file and surely enough there were hidden zipped files within it.

![Untitled](351fc577_Untitled.png)

<br/>

Next, I used the command `binwalk --extract flag.png` to extract the contents hidden within the image file.

![Untitled](a4eada13_Untitled.png)

<br/>

Inside of the extracted folder, I found a directory named secret and decided to look inside of it.

![Untitled](652f7e19_Untitled.png)

<br/>

Inside of this directory contained an image file which also named **flag.png. **Opening up the image file I found was the flag. 

![Untitled](32d4bf0b_Untitled.png)

<br/>

**Flag: picoCTF{Hiddinng_An_imag3_within_@n_ima9e_ad9f6587}**

<br/>

# <u>Web Exploitation</u>

## <u>Challenge: findme</u>

![Untitled](0ae17374_Untitled.png)

<br/>

For this challenge, I first first went to the website and checked its contents. It appeared to be a standard login page.

![Untitled](e29faeb7_Untitled.png)

<br/>

I also checked the page source to see if there was anything sketchy. However, I couldn’t find anything that looked out of place.

![Untitled](34f8fe89_Untitled.png)

<br/>

Next, I tried to login with the credentials provided in the challenge description which worked accordingly.

![Untitled](f3972752_Untitled.png)

<br/>

Upon logging in, I was redirected to another page. The page had a search box with a message asking to search for flags which could possibly hint for an injection attack.

![Untitled](31e1b249_Untitled.png)

<br/>

I tried viewing the page source first to find any useful information, however, there was nothing out of the ordinary. 

![Untitled](12fff07c_Untitled.png)

<br/>

I then tried various different injections to see if they worked but none of them seemed to work. I then returned back to the login page to see if I missed anything. After looking through everything, I was still unable to find a hint, so I tried logging in again.

![Untitled](ef0bb6b6_Untitled.png)

<br/>

It was then I noticed something odd on the login page after that. I noticed URL bar had two different redirections prior to reaching the `/home` directory on the website. If the redirections are too quick when trying to copy and paste them, I would suggest screen recording and typing them out manually.

![Untitled](3580d7ed_Untitled.png)

![Untitled](9290aed2_Untitled.png)

<br/>

Taking a closer look at the URLs during the rediretion process, I noticed that they looked like Base64 encodings. I then copied them quickly during the redirection process, combined them and put them into CyberChef’s Base64 decoder. After decoding it, I was able to obtain the flag.

![Untitled](592b530b_Untitled.png)

**Flag: picoCTF{proxies_all_the_way_25bbae9a}**

<br/>

## <u>Challenge: MoreSQLi</u>

![Untitled](ccec499c_Untitled.png)

This challenge is essentially a typical login bypass SQL injection challenge with a slight twist.

<br/>

![Untitled](cf2ad049_Untitled.png)

The image above shows what looks to be a login page on the challenge website. 

<br/>

![Untitled](593a2c41_Untitled.png)

When testing with basic credentials such as the username “admin” and the password “admin” an SQL error message is displayed which is a security issue. In this case, it even displays the order in which the user credentials are checked. More information on this below.

<br/>

![Untitled](9cfde4d6_Untitled.png)

![Untitled](91b30ae6_Untitled.png)

In order to better test this, I had used Burp Suite to intercept the requests with some random credentials.

<br/>

<br/>

![Untitled](32818fb7_Untitled.png)

The request is then sent to the repeater to do further testing.

<br/>

<br/>

![Untitled](15f10c8a_Untitled.png)

I then tried to perform a basic SQL Injection attack to bypass the login page. In this case, the query is injected within the `username` parameter whereby the full query is ** **`**' or 1=1--**`** . **The query essentially makes the query true as `1=1` and comments out the password which allows us to login as the first valid user (usually admin account). However, the injection failed as seen in the HTTP response.

<br/>

![Untitled](37c2fb11_Untitled.png)

I then remembered that the SQL query used on the server for the login page checks for the password first before the username. Hence, this meant that the SQL query needs to be injected within the password parameter instead.

<br/>

<br/>

![Untitled](0a8b8b92_Untitled.png)

Therefore, I had switched the order of the request parameters and sent request which worked provided the flag.

<br/>

**Flag: picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_c8ee9477}**

<br/>

<br/>

<br/>

