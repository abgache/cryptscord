# CryptScord V2
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
Small program to send/receive messages using [Discord](https://discord.com/) while adding a layer of encryption.

> [!IMPORTANT]
> This is a test, all this project was made 100% by (ChatGPT)[https://chatgpt.com/].
> Please read 

> [!WARNING]
> **USE AT YOUR OWN RISK — READ CAREFULLY**
>
> CryptScord is an **experimental, unofficial and unaudited project**.
>
> ### Discord-related risks
> - This tool **violates Discord Terms of Service** by requiring a **user token**.
> - Your account **can be limited, locked, or permanently banned**.
> - Discord can still access:
>   - message timestamps
>   - channel IDs
>   - user IDs
>   - traffic patterns and metadata
> - Discord infrastructure is **NOT trusted** in this threat model.
>
> ### Security & privacy risks
> - This software has **NO security audit**.
> - Cryptographic implementation may contain **critical vulnerabilities**.
> - Encryption **does NOT mean anonymity**.
> - A malicious or modified client can:
>   - log plaintext messages
>   - leak keys
>   - impersonate a peer
> - Man-in-the-middle attacks are **NOT fully prevented**.
>
> ### User responsibility
> - You are **100% responsible** for how you use this software.
> - The author takes **NO responsibility** for:
>   - account bans
>   - data loss
>   - leaks
>   - legal consequences
>
> ### Strict usage rules
> Do NOT use for:
> - illegal activities
> - harassment, stalking, or abuse
> - bypassing laws or platform protections
> - sensitive, personal, or life-critical communications
>
> By using CryptScord, **you acknowledge all these risks and accept them fully**.

---

## How does it work?
The 2 users have to write their token and the channel ID, then it will automatically share an AES key using the RSA algorithm then you will be able to send messages, they will be crypted on discord and decrypted by the other clients.  
You may experience latency (a lot) but no worries it's normal. a message can take up to 1minute to be received by the other client.
And when leaving just write ``exit`` or Ctrl + C and it's gonna delete all __your__ messages.

---

## How to use it?
Before testing it, you will need to know your [discord token](https://www.youtube.com/watch?v=ECHX8iZeC6o).
### 1st stage : How to get CS files on my computer?
> [!IMPORTANT]
> To use CryptScord, you will need: [Python 3.10](https://www.python.org/downloads/release/python-31010/) + [Git](https://git-scm.com/install/)  
**First, clone the repo:**  
```batch
   git clone https://github.com/abgache/cryptscord.git
   cd cryptscord
```
**Then, download the requirements:**  
```batch
   pip install -r requirements.txt
```
**Finnally, start your session:**
```batch
   python main.py
```
Then write your token and the channel ID (only tested on private messages).
