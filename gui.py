import hashlib
import base58
import binascii
import requests
import tkinter
import customtkinter
import socket
import time
import os
import subprocess
import multiprocessing
#import pyopencl as cl
import numpy as np
from multiprocessing import Process
from pypresence import Presence
from ecdsa import SigningKey, SECP256k1



window_title = 'Militarized Wallet Cracker'
webhook_url = 'Your_Webhook_URL'    # <-- Change this
file_path = 'real.txt'
version = 0.3


def DRPC():
    client_id = "1199083933955018863"
    RPC = Presence(client_id)
    RPC.connect()
    RPC.update(state="Mining Bitcoin with MWC!" ,
        start = int(time.time()),
        large_text="Developed by 4G0NYY",
        large_image="mew" ,
        small_image="small2",
        small_text="hardtruth",
        buttons=[{"label": "GitHub", "url": "https://github.com/4G0NYY/MWC-Public"}, {"label": "Discord", "url": "https://discord.gg/ZhtcnQsbZz"}])


def send_webhook_message(data):
    response = requests.post(webhook_url, json=data)
    if response.status_code == 204:
        print('Webhook message sent successfully.')
    else:
        print('Failed to send webhook message.')


def import_pubkeys(file_path):
    try:
        with open(file_path, 'rb') as file:
            contents = file.read()
            return contents.decode('utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        # will have to put an error message in here
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


btc = import_pubkeys(file_path)


def stop():
    exit()


def startMiner():
    workers = workerint.get()
    with multiprocessing.Pool(processes=workers) as pool:
        # Map the Miner function to each process
        freeze_support()
        pool.map(Miner)

def Miner():
    count = 1
    interval = 3600
    next_report_time = time.time() + interval
    start = int('000000000000000000000000000000000000000000000002c000000020449e9c', 16)
    end = int('000000000000000000000000000000000000000000000003ffffffffffffffff', 16)


    for i in range(start, end + 1):
        puzzleaddr = btc
        private_key_hex = binascii.hexlify(os.urandom(32)).decode('utf-8')
        key_bytes = binascii.unhexlify(private_key_hex)
        sk = SigningKey.from_string(key_bytes, curve=SECP256k1)
        vk = sk.get_verifying_key()
        public_key_bytes = b'\x02' + vk.pubkey.point.x().to_bytes(32, 'big') if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.pubkey.point.x().to_bytes(32, 'big')
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()
        extended_ripemd160_hash = b'\x00' + ripemd160_hash
        sha256_hash = hashlib.sha256(extended_ripemd160_hash).digest()
        sha256_hash = hashlib.sha256(sha256_hash).digest()
        checksum = sha256_hash[:4]
        binary_address = extended_ripemd160_hash + checksum
        address = base58.b58encode(binary_address).decode('utf-8')


        if address == puzzleaddr:
            print(f"WE RICH!! Address: {address}, Hex Key: {private_key_hex}")
            with open('hits.txt', 'a') as file:
                file.write("Address: {address} Hex-Key: {private_key_hex}")
            data1 = {
                'content': f"WE RICH AF BOYYYY!!\n Address: {address}\n Hex-Key: {private_key_hex}\n"
            }
            send_webhook_message(data1)
            break
        else:
            print(f"[{count}] Address: {address} | Hex Key: {private_key_hex}")

        count += 1

        current_time = time.time()
        if current_time >= next_report_time:
            ip_address = socket.gethostbyname(socket.gethostname())
            data = {
                'content': f"Scanned keys: {count}\nStart Key: {hex(start)}\nEnd Key: {hex(end)}\nIP Address: {ip_address}"
            }
            send_webhook_message(data)
            next_report_time = current_time + interval


customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("blue")

app = customtkinter.CTk()
app.geometry("720x480")
app.title("Militarized Wallet Cracker")

title = customtkinter.CTkLabel(app, text="Welcome to the Militarized Wallet Cracker!")
title.pack(padx=4, pady=10)

discord = customtkinter.CTkLabel(app, text="Join my Discord for Help: https://discord.gg/gpt4k7jBbv")
discord.pack(padx=4, pady=4)

drcpvar = tkinter.StringVar()
dunno = customtkinter.CTkEntry(app, width=40, height=40, textvariable=drcpvar)
dunno.pack()

workerint = tkinter.IntVar()
dunno2 = customtkinter.CTkEntry(app, width=40, height=40, textvariable=workerint)
dunno2.pack()


idfkanymore = customtkinter.CTkButton(app, text="Start Mining", command=startMiner)
idfkanymore.pack()

idfkanymore2 = customtkinter.CTkButton(app, text="Stop Mining", command=stop)
idfkanymore2.pack()

app.mainloop()