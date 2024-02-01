@echo off
echo Installing Python 3.12.1...
python -m pip install --upgrade pip
python -m pip install python==3.12.1
echo Python 3.12.1 installed successfully!

echo Installing required packages...
python -m pip install hashlib base58 binascii bip32utils requests socket time threading os mmap pypresence ecdsa
echo Required packages installed successfully!

echo Install completed.