#    AgentTesla v4
SHA256:812b79890b4f2f12bbf6feda239d5daa55bb4870aef44cc01621a02f1fad4814

# Brief Introduction : What's AgentTesla ?
A .NET based information stealer. The malware is able to log keystrokes, can access the host's clipboard and crawls the disk for credentials or other valuable information. It has the capability to send information back to its C&C via HTTP(S), SMTP, FTP, or towards a Telegram channel.

#    Extraction
Malware performs within 3 different dll to reach the final payload which is payload_slayed.exe in the below picture, they all use **Eziriz .NET Reactor** to obfuscate dlls

![](https://hackmd.io/_uploads/r1QkkTkXa.png)


#    Persistence
You can see the malware is checking whether the startup directory exist or not, if not it will create a new one, next it will check the exe exist or not, if yes the victim will be assumed infected so the program will kill the process to make sure things don't go wrong.

The final stage in persistence end up with setting value in registry to make sure the program execute automatically after every reboot.

![image.png](https://hackmd.io/_uploads/HkL80JZ7a.png)
![image.png](https://hackmd.io/_uploads/ByJoJxbmT.png)
![image.png](https://hackmd.io/_uploads/ByfgbeWXT.png)


#    Behavior
Just like others AgentTesla malware performs credential stealing behavior, you can see it in below picture, it has all kind of options about web credentials and mail service, there's more(Windows Credentials) about it(check second picture) but I will just stay focus on the important part, **the list in the first picture is the enumerator trying to search a file called "Login Data" and try to search a table called "logins"**

![](https://hackmd.io/_uploads/SJKh2xMzT.png)
![](https://hackmd.io/_uploads/Sk9rgpkQa.png)
![](https://hackmd.io/_uploads/HkeIYnkXa.png)

The above picture is the "logins" table which stored url, username and its password information. 

And the below one also trying to find the login data, but the malware developer separate two lists by the file name(Login Data and profiles.ini), it first need to find a file called profiles.ini, this file stores the path where the real profile exist to find rest of the username and password just like the malware do previously.
![](https://hackmd.io/_uploads/rkeX0xGz6.png)

**And of course keylogged & screenshot**
![image](https://hackmd.io/_uploads/HJBDwv946.png)

![image](https://hackmd.io/_uploads/SJ20wgsET.png)

![image](https://hackmd.io/_uploads/HkET1WsN6.png)

From above pictures you can see that the program check the logged_keys after elapsed event happened the A.B.A() function send the logged_result to the remote smtp server

![image](https://hackmd.io/_uploads/By9Kv_qE6.png)








#    C2
The program end up with sending the data it found with SMTP to the C2 server called **mail.awelleh3.top** you can see there's a memorystream in the picture, it's the attachment for the file it found and the path name "zugijqnz.hq3" is randomly creates.
![image.png](https://hackmd.io/_uploads/rkTx3gWmp.png)
![](https://hackmd.io/_uploads/ByB563176.png)
![](https://hackmd.io/_uploads/S1PFC3J7a.png)
![](https://hackmd.io/_uploads/HJl_mC2J7T.png)


Actually there's more function in this malware like keylogger etc, but I'm not going to introduce all of them in this article.

#    Yara
```
rule AgentTesla
{
	meta:
		Author = "Alex"
		Malware = "AgentTesla.v4"
		description = ""
		sha256 = "812b79890b4f2f12bbf6feda239d5daa55bb4870aef44cc01621a02f1fad4814"
	strings:
	
		$dos_header = {4D 5A}
		//$pe_signature = {50 45 00 00}
		
		$s1 = "Opera Browser" ascii
		$s2 = "Yandex Browser" ascii
		$s3 = "Iridium Browser" ascii
		$s4 = "Chromium" ascii
		$s5 = "7Star" ascii
		$s6 = "Torch Browser" ascii
		$s7 = "Cool Novo" ascii
		$s8 = "Rometa" ascii		
		$s9 = "Chrome" ascii
		$s10 = "Edge Chromium" ascii
		$s11 = "Firefox" ascii
		$s12 = "Thunderbird" ascii
		$s13 = "IE/Edge" ascii
		$s14 = "Safari for Windows" ascii
		$s15 = "QQ Browser" ascii
		$s16 = "Outlook" ascii
		$s17 = "Windows Mail App" ascii
		$s18 = "FileZilla" ascii
		$s19 = "FtpCommander" ascii
		$s20 = "OpenVPN" ascii
		$s21 = "NordVPN" ascii
		$s22 = "Discord" ascii
		$s23 = "MysqlWorkbench" ascii
		$s24 = "Internet Downloader Manager" ascii
		
		$login = "Login Data" ascii
		$cookie = "Cookies" ascii
		$profile = "profiles.ini" ascii
		$cookilite = "cookies.sqlite" ascii
		
	condition:
		$dos_header at 0 and uint32(uint32(0x3C)) 
		and
		3 of ($s*) or
		1 of ($login,$cookie,$profile,$cookilite)

}
```


#    IOC

**Domain**:
mail.awelleh3.top
api.ipify.org
api4.ipify.org


**IP**:
173.231.16.76 US
185.198.59.26 United Arab Emirates


**Registry**:
**HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\PgIBeC**![](https://hackmd.io/_uploads/Hy-rchJXa.png)



CO(cookies) SC(screenshot) KL(keylogger)