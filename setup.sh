#!/usr/bin/env bash

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

if command_exists termux-setup-storage; then
    termux-setup-storage
    pkg update && pkg upgrade -y && pkg install python wget git build-essential binutils pkg-config openjdk-17 -y
else
    sudo -k apt update && sudo -k apt upgrade -y && sudo -k apt install wget git build-essential binutils pkg-config openjdk-17-jdk python3 python3-pip python-is-python3 -y
fi

if ! command_exists radare2; then
    git clone https://github.com/radareorg/radare2
    radare2/sys/install.sh
fi

wget -q --show-progress https://github.com/REAndroid/APKEditor/releases/download/V1.4.1/APKEditor-1.4.1.jar -O src/bin/apkeditor.jar

pip install -r requirements.txt

printf "ALL DONE\n"