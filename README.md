<br/>
<h1>PicoCTF 2023 Writeup</h1>

![a8ddf567_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/6c1e391d-c1c2-411f-8b17-c54a625082ca)

Unfortunately, the following write-up that I have created does not consist of a write-up for every single challenge that I had done but it does consist of a large majority of challenges. Also, this does not include any write-ups for the General Skills challenges.

# <u>Binary Exploitation Challenges</u>

## <u>Challenge: two-sum</u>

The challenge below involves a file which is vulnerable to an integer overflow. When an integer overflow is caused and the necessary conditions are met to solve the challenge the program will display the flag. An integer overflow occurs when an arithmetic operation attempts to create a numeric value which is beyond the number of digits which is used to represent it. The reason I was able to deduce that it is an integer overflow comes from the hints which suggest that it’s not a traditional math problem and more so an issue with the program.

![a2942fce_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/6108e66b-8fe2-4320-96e7-db77bb6a9064)

<br/>

This challenge provides the source code, so I started by downloading and opening it to understand how the program functions. 

![c0d022df_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/72639600-9563-46f3-b7ce-8f2eab189824)


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

![e3149cf8_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/b2a3cd42-cbf8-4b7a-94b6-aacb0fbb81b1)

<br/>

Another thing to note for these types of challenges is whether it uses signed or unsigned integers. Unsigned integers only involve positive numbers and fall into the maximum integer range mentioned before. However, this challenge involves signed integers, hence, the integer range in this case is between **-2147483648 **and **2147483647. **

<br/>

Therefore, in order to cause an integer overflow with both the numbers added together I used the numbers **2147483647 **and added it by **1 **to cause an integer overflow which caused the sum to be **-2147483648. **This is proven when connecting to the server via `netcat` and inputting the two numbers mentioned, thus, giving me the flag.

![cc5b056d_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/800e889b-4071-4705-bfbc-13bd2004c6c6)

<br/>

**Flag: picoCTF{Tw0_Sum_Integer_Bu773R_0v3rfl0w_ccd078bd}**

<br/>

## <u>Challenge: VNE</u>

This challenge involves the exploitation of a binary file by injecting commands into the environment variable so that it executes our arbitrary commands. An environment variable is commonly used by Linux programs and scripts to store and retrieve information related to the operating system environment such as paths, user names, default shell and more. Some of the main hints are provided in the challenge tags and the title of the challenge which is “ENV” backwards.

![5cf8576c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/d151171d-c093-4d49-b8af-e50792b15635)

<br/>

This challenge provides the SSH (Secure Socket Shell) credentials that allowed me to connect to the remote server. Command to connect to the server `ssh -p [PORT_NUMBER] ctf-player@saturn.picoctf.net` along with the password `8a707622`. 

![0ffbc4fc_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/e81c3f63-db24-4251-9e23-ba6269595a9c)

<br/>

Upon connecting to the server via SSH. I found the 64-bit binary file named `bin` within the home directory of the user. Additionally, the file is owned by the **root **user.

![c1bf45a8_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/3f81148a-cf69-4417-be54-b29fbb454c78)

<br/>

When trying to execute the file, it displayed an error message stating that one of the environment variables were not set. 

![438f9998_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/652dd2f3-c1c8-4706-931c-537f627402c3)

<br/>

Looking at the environment variables via the command `env` I wasn’t able to find any environment variables named** “SECRET_DIR”**. 

![0c1becf1_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7e64026e-ffab-4780-9d64-ce555a9357b5)

<br/>

As the program required the** “SECRET_DIR”** environment variable, I decided to set the variable and inject my own **bash **commands within the variable. The command I used was `export SECRET_DIR="ls /challenge"` . I then verified if my environment variable was set using `env` once again.

![d01d0215_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/277d2fba-e5c9-465e-a884-204894768a58)

<br/>

With that, I ran the `bin` binary again to see if the bash command injected into the environment variable would actually work. It was able to show me a `flag.txt` file within the `/root` directory. 

![c35b2922_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/d38e3298-c116-4b0e-84b4-8c4eefcebb05)

I then added an extra command in the environment variable so that it would also read out the contents of the file named `flag.txt`. The command used was `export SECRET_DIR='/root && cat /root/flag.txt'` . With that, I executed the file and was provided with the flag.

![09eb0179_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/30d04be6-1cfb-4258-bc54-81414c63a54e)

<br/>

**Flag: picoCTF{Power_t0_man!pul4t3_3nv_3f693329}**

## <u>Challenge: hijacking</u>

The main hints for this comes from the tags which point to a **privilege escalation** which is a term for obtaining higher privileges for hosts we have access to. Another hint is located within the challenge description which points out that there is a Python file within the server that can be exploited to obtain higher-level privilege. The other 2 hints provided in the challenge just show where the hidden Python file can be found.

![a0671168_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/33f3cfcd-91b9-4a33-bace-0a8314e7b6f3)

<br/>

For this challenge, I first connected, to the server via SSH using the credentials provided. SSH command: `ssh -p [PORT_NUMBER] picoctf@saturn.picoctf.net`

![ba47fb76_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/846580fd-3076-4499-a288-74fd44eb2aa4)

<br/>

First, I searched for the Python file which I found was located in the directory `/home/picoctf`. It was a hidden file within the directory which we can use `ls -al`. The name of the file was `.server.py` which was owned by the **root** user.

![78664422_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/dd0decfd-a892-4e34-ba52-4828ae3ee59a)

<br/>

Taking a further look at the Python file using the `cat` command, I was able to read the source code of the file which was essentially to ping a host and gather information about the host.

![d1b7318b_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/365fd970-7246-4b35-9350-83df9fa504f1)

Something important to note is that the source code involved the use of some python libraries. This could be used to my advantage by changing the contents of the libraries to instead execute my code. 

<br/>

Running `sudo -l`  in the terminal shows us that we are able to execute certain commands as **root. **One of those commands is `/usr/bin/vi` (vim → text editor) which can be run by all users. Hence, we can use this to edit the files despite being owned by the root user. Another command we have access to is also to run the `.server.py` file as root without requiring a password. 

![5220f11a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a888348f-71c0-4a39-b7b8-86f1e46127ba)

<br/>

With this information, I realised that I needed to hijack one of the Python libraries that were imported in the `.server.py` file with my own code to escalate to **root privilege.** Hence, I made a new `base64.py` file to which I put my own code into so that the Python file would instead import the contents of my file instead of the actual base64 python library. 

![f5077a54_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/fa04ff6f-398d-465b-bd0f-1da92f60ff88)

<br/>

The code that I used involved the `os` library so I can spawn a bash shell. If the program were to be run with `sudo` it should spawn a shell as **root.**

![3f7c966a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/2c845dff-c024-4442-9722-08dbfdc820c1)

![48e51ebd_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/046d4a6a-d2f3-433c-9b51-658296a3badb)

After creating the new `base64.py`, I then ran the `.server.py` file using the command `sudo /usr/bin/python3 /home/picoctf/.server.py`  which spawned a root shell.

![20fc1132_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/cefd14fd-273d-4b61-8f1e-bc5eb95785df)

<br/>

With this, I was able to obtain **root** privileges and was able to navigate to the `/challenge` directory and found a file named `metadata.json` which contained the flag. 

![2c3d4138_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/f5198465-85da-47cf-b90a-5c291fe243b4)

<br/>

**Flag: picoCTF{pYth0nn_libraryH!j@CK!n9_f56dbed6}**

<br/>

## <u>Challenge: HideToSee</u>

This is a very simple challenge that involves image steganography. Steganography is the practice of hiding messages or information within files such as audio and image files (basically not displaying the text). The information or data can be obtained by extracting the contents from the file itself. One of the main hints of this challenge is provided, which is i to download and extract the contents from the image.

![1acb85eb_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/337edc5c-bb90-4a93-ab61-470bb6bf251d)

<br/>

Firstly I started by downloading the image file from the challenge description and observing it. The image essentially showed what the Atbash cypher looked like. 

![92f01c8c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/88a3dd22-6cbf-4b95-99da-72872886808e)

![f10b6a0a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/06ab6db2-2b54-443d-9cde-262de8edcd1c)

<br/>

Next, I opened up the terminal and used steghide to see if there was anything hidden within the `atbash.jpg` image file. The command used is `steghide --info atbash.jpg`. 

![bc7920e7_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/1588658a-a6d2-4d57-98a9-7c85e1212027)

In this case, the image did not require a passphrase to view the contents which made it even easier. As seen in the image above, the image file contains a file within it called **encrypted.txt.**

<br/>

With this knowledge, I then used **steghide** once again to extract the contents hidden within the image file using the command `steghide extract -sf atbash.jpg` without a passphrase.

![a601739d_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/08642fa8-e928-4aae-841b-646b64ebe3ce)

![2e6ff67c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/111e9d64-cca1-4563-b087-6c9af3a7e8d0)

<br/>

I then checked the contents of the **encrypted.txt **file and found something that looked similar to a flag. 

![9e7dbf48_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/458ddb2c-7230-4668-8deb-a3bd6e583319)

<br/>

I then remembered another hint which was the Atbash cipher in the image from before. So I instictively tried to decipher it using **[CyberChef](https://gchq.github.io/CyberChef/#recipe=Atbash_Cipher()&input=a3J4bFhHVXt6Z3l6aHNfeGl6eHBfencyMXl4Mnh9)****. **With this, I was able to obtain the flag and solve the challenge.

![d638e0da_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7c11656c-284e-4ba3-aeef-8c88e4722f4f)

<br/>

**Flag: picoCTF{atbash_crack_ad21bc2c}**

<br/>

## <u>Challenge: ReadMyCert</u>

The challenge below uses a CSR (Certificate Signing Request) file which is one normally one of the first steps when trying to get an SSL/TLS certificate. This challenge provides us with a CSR file in hopes of trying to decipher it and find the flag. 

![8c29dceb_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/5fdb1a59-d8a3-4514-857d-29c9f460ba89)

<br/>

For this challenge, I first downloaded the file provided in the challenge  and used the `cat` command to view the contents of the file. 

![e593be6a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/8f99e46b-b50f-441f-8719-a74ba4d93fcb)

<br/>

As it was a certificate request, I used  `openssl`  which is a command line tool used to generate private keys, create CSRs, install SSL/TLS certificates and even identify information about certificates. The command I used is  `openssl req -in readmycert.csr -noout - text`  to decipher the contents of the **readmycert.csr** file.

<br/>

**Command Breakdown:**

`req` → Specifies that the file is a CSR file

`-in` → Specifies the input for the file which is **readmycert.csr**

`-noout` → Ensures that openssl does not output any information to the terminal or the file

`-text`  → For the output of the CSR file to be in a textual and human-readable format

<br/>

![2ef9f08e_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7622f58e-53c1-4350-8c47-76d1191bcf7b)

Within the deciphered CSR file, we are able to find the flag.

<br/>

**Flag: picoCTF{read_mycert_cda8cb26}**

<br/>

## <u>Challenge: rotation</u>

This is also another Cryptography challenge involving the shifting of characters hence the name “rotation”. 

![04e91167_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/0aadce17-4fef-434d-bb0c-9a04a643acd3)

<br/>

I started by first downloading the file **encrypted.txt **which was provided in the challenge and viewed its contents using the `cat` command. 

![c95c9251_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7b9a2ca6-cc98-4da8-b0d5-6ecfb019dd78)

The text within the file seemed to resemble the flag however the characters were shifted which brought up the possibility that it could be a ROT-13 or Caesar Cipher. 

<br/>

Hence, I opened up CyberChef and checked if it was a ROT-13 cypher which is a forward shift of 13 characters.

![b3433456_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/58cb267f-4536-4c7d-89a3-7d80e49e7907)

<br/>

Since that wasn’t the case, I attempted to change the number of characters it was shifted by to hopefully find the flag. Eventually, I stumbled upon it by increasing the number of shifted characters to 18 which revealed the flag. 

![8947cdd8_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/f277e292-fdf1-4a9a-a28f-578cddf692db)

**Flag: picoCTF{r0tat1on_d3crypt3d_bdf2f252}**

<br/>

# <u>Forensics</u>

## <u>Challenge: hideme</u>

This is a simple challenge involving the use of image steganography. The main hints of this challenge are found within the tags and description of the challenge itself. 

![d8b27260_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/2663d1d8-6adf-4e2e-bc22-b1d85d18f5ea)

<br/>

For this challenge, I first started by downloading the image provided in the challenge description. The name of the file was `flag.png` and it was the PicoCTF logo. 

![4cd20f94_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/0fe7b5ba-e3ba-4628-8cba-72708383c64c)

<br/>

I then used `binwalk` which is a popular tool used to analyze and extract information from image files. Firstly, I used the command `binwalk flag.png`  to identify if there were any files contained within this file and sure enough there were hidden zipped files within it.

![351fc577_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a0e2993c-e73e-4afd-9080-fd13b919773d)

<br/>

Next, I used the command `binwalk --extract flag.png` to extract the contents hidden within the image file.

![a4eada13_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/adc8952f-e2a5-467a-974c-50f13a21a145)

<br/>

Inside the extracted folder, I found a directory named **secret** which I had looked into.

![652f7e19_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/bb133fec-30e5-4fdb-837b-6b77c71ba87a)

<br/>

Inside this directory contained an image file which is also named **flag.png. **Opening up the image file I found the flag. 

![32d4bf0b_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/0a135942-8958-467f-b97b-d1d8f7f8930e)

<br/>

**Flag: picoCTF{Hiddinng_An_imag3_within_@n_ima9e_ad9f6587}**

<br/>

# <u>Web Exploitation</u>

## <u>Challenge: findme</u>

![0ae17374_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/1396d109-7d6d-4f58-8f44-853d257132fb)

<br/>

For this challenge, I first went to the website and checked its contents. It appeared to be a standard login page.

![e29faeb7_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/1ef9a77b-460f-4de3-b571-3d4b5231d1c7)

<br/>

I also checked the page source to see if there was anything sketchy. However, I couldn’t find anything that looked out of place.

![34f8fe89_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/5746a57f-907a-44f4-a210-e9f0b123cddf)

<br/>

Next, I tried to log in with the credentials provided in the challenge description which worked accordingly.

![f3972752_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/9c57b6c5-d945-4e4a-8549-09e33b07df1a)

<br/>

Upon logging in, I was redirected to another page. The page had a search box with a message asking to search for flags which could possibly hint at an injection attack.

![31e1b249_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/e6b08e08-b999-4731-baf3-63cd1d6b6a2c)

<br/>

I tried viewing the page source first to find any useful information, however, there was nothing out of the ordinary. 

![12fff07c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/c63e2d1e-1ff4-4cf1-ae49-8a621181786f)

<br/>

I then tried various different injections to see if they worked but none of them seemed to work. I then returned back to the login page to see if I missed anything. After looking through everything, I was still unable to find a hint, so I tried logging in again.

![ef0bb6b6_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/14c6f942-03de-420b-9e51-cf3423d834ce)

<br/>

It was then I noticed something odd on the login page after that. I noticed the URL bar had two different redirections prior to reaching the `/home` directory on the website. If the redirections are too quick when trying to copy and paste them, I would suggest screen recording and typing them out manually.

![3580d7ed_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/5fbc7e22-d715-4e5c-869f-ddd91470ee81)

![9290aed2_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/6788e478-2ead-418a-ac44-99f0eed1ba6f)

<br/>

Taking a closer look at the URLs during the redirection process, I noticed that they looked like Base64 encodings. I then copied them quickly during the redirection process, combined them and put them into CyberChef’s Base64 decoder. After decoding it, I was able to obtain the flag.

![592b530b_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a79a64fb-3d5f-4916-b3e5-b29c01ec2d81)

**Flag: picoCTF{proxies_all_the_way_25bbae9a}**

<br/>

## <u>Challenge: MoreSQLi</u>

![ccec499c_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/88631bcd-82df-446d-9a9a-08f0cf16a1f2)

This challenge is essentially a typical login bypass SQL injection challenge with a slight twist.

<br/>

![cf2ad049_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/29309575-97eb-495c-a3dc-d4b0a29c9620)

The image above shows what looks to be a login page on the challenge website. 

<br/>

![593a2c41_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/77d8b713-5b2b-4190-a793-bb5e9feededb)

When testing with basic credentials such as the username “admin” and the password “admin” an SQL error message is displayed which is a security issue. In this case, it even displays the order in which the user credentials are checked. More information on this is below.

<br/>

![9cfde4d6_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/a04365cf-f5e9-4a87-beaf-ca8132e930f9)

![91b30ae6_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/cf106e49-b404-4554-b8a8-083468b7ba59)

In order to better test this, I had used Burp Suite to intercept the requests with some random credentials.

<br/>

<br/>

![32818fb7_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/7b7a6fb8-261b-4f9f-907b-a01c8bd33276)

The request is then sent to the repeater to do further testing.

<br/>

<br/>

![15f10c8a_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/23821c86-f1b6-4758-8b16-38bee1bb9f4e)

I then tried to perform a basic SQL Injection attack to bypass the login page. In this case, the query is injected within the `username` parameter whereby the full query is ** **`**' or 1=1--**`**. **The query essentially makes the query true as `1=1` and comments out the password which allows us to log in as the first valid user (usually admin account). However, the injection failed as seen in the HTTP response.

<br/>

![37c2fb11_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/66e29f29-cee0-4845-95de-27efcc24f1ae)

I then remembered that the SQL query used on the server for the login page checks for the password first before the username. Hence, this meant that the SQL query needs to be injected within the password parameter instead.

<br/>

<br/>

![0a8b8b92_Untitled](https://github.com/Fedwig/PicoCTF2023/assets/85858497/63d4a282-ece5-4a47-ab72-fd372ec5836e)

Therefore, I switched the order of the request parameters and sent a request which worked and provided the flag.

<br/>

**Flag: picoCTF{G3tting_5QL_1nJ3c7I0N_l1k3_y0u_sh0ulD_c8ee9477}**

<br/>

<br/>

<br/>

