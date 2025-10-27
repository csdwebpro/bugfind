#!/bin/bash

echo -e "\033[1;34mInstalling BlackHat Recon Pro...\033[0m"

# Update system
sudo apt update && sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3 python3-pip git nmap whois dnsutils

# Install Go if not present
if ! command -v go &> /dev/null; then
    wget https://golang.org/dl/go1.20.linux-amd64.tar.gz
    sudo tar -C /usr/local -xzf go1.20.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
    source ~/.bashrc
fi

# Install Python packages
pip3 install -r requirements.txt

# Install Go tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/michenriksen/aquatone@latest

# Update nuclei templates
nuclei -update-templates

# Make script executable
chmod +x blackhat_recon.sh

echo -e "\033[1;32mInstallation completed! Configure your API keys in .env file\033[0m"
