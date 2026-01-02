# Passive DNS Educational Tool

INTRODUCTION : Subdoamin finding tool passively the main feature of this tool is that the all requests send through tor network it send one request in 4 to 5 second it is slow but user stay total anonmous

## ⚠️ Legal & Ethical Notice

**This tool is for EDUCATIONAL PURPOSES ONLY.**

### ✅ Permitted Uses:
- Learning DNS and network security concepts
- Testing on systems you own or control
- Authorized security assessments (with written permission)
- Academic research projects

### ❌ Prohibited Uses:
- Scanning systems without explicit permission
- Unauthorized security testing
- Any illegal activities
- Privacy violations or harassment

**The authors are not responsible for misuse.**

## 🛠️ Features

### Features:
- **Rate Limited**: Conservative request timing (6-12 requests/minute)
- **Privacy Focused**: Optional Tor integration for privacy 
- **Wordlist Support**: Learn about common subdomain patterns
- **Color-coded Output**: Clear visual feedback for learning
- **File Export**: Save results for analysis

### Technical Features:
- **Pure C Implementation**: Fast, lightweight, no dependencies
- **Tor Integration**: Learn about onion routing and privacy
- **Modular Design**: Easy to understand and modify
- **Educational Prompts**: Requires acknowledgment of ethical use
- **Detailed Logging**: Understand what's happening at each step

## 🚀 Quick Start

### Prerequisites:
- GCC compiler
- libcurl development libraries
- Tor (optional, for privacy mode)

### Installation:
```bash
# Clone repository
https://github.com/bughunter-18118/Passive-Dns-Researcher.git
cd Passive-Dns-Researcher

# Install dependencies
sudo apt install gcc libcurl4-openssl-dev

# Compile
gcc shadowscan.c -o subdomainscanner -lcurl

# Tor setup for tool(Just do it once)
sudo apt install tor -y
sudo nano /etc/tor/torrc

*In opened file find word ControlPort using ctrl+b and search word and if she hash in front of Control Port remove the hash from in front of the Control Port.
*And do same with word 'CookieAunthetication' and SocksPort and after doing this press button ctrl+x type y and press enter button*

# Enable tor 
sudo systemctl start tor
sudo systemctl enable tor

# Run tool give domain and kali wordlist 
./subdomainscanner example.com usr/share/seclists/Discover/DNS/subdomains-top1million-110000.txt

![image alt](https://github.com/bughunter-18118/Passive-Dns-Researcher/blob/043c4453c35d5b639186237800c851fc9c10b5ac/tool.JPG)

# To see requests are going through tor network or not
sudo tcpdump -i lo -n "port 9050" -v

*You will see the requests going through tor network*






