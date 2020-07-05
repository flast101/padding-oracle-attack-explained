# Padding Oracle Attack Explained
Padding Oracle attack fully explained and coded from scratch in Python3.


## Theory and Explanation
You will find here explanation of the CBC mode vulnerability and how to exploit it. This part is under construction in the [Wiki Page](https://github.com/flast101/padding-oracle-attack-explained/wiki).


## Usage

~~~
$ python3 poracle_exploit.py <message>         decrypts and displays the message
$ python3 poracle_exploit.py -o <hex code>     displays oracle answer

Cryptographic parameters can be changed in settings.py
~~~

## Example

~~~
root@kali:~# python3 poracle_exploit.py 5c448a498fb642915c20ba4df9decf5c2b13306b12f1102dfbace8c38b353ff8
Decryptded message:  I am not encrypted anymore.
~~~


Happy hacking ! :smiley:

[<img src="http://www.hackthebox.eu/badge/image/249498" alt="Hack The Box">](https://www.hackthebox.eu/profile/249498)   
[![thm_badge](https://github.com/flast101/profile/blob/master/images/sig_thm_omni.png "thm_badge")](https://tryhackme.com/p/D3rf)

