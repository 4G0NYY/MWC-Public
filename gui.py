import hashlib
import base58
import binascii
import requests
import tkinter
import customtkinter
import ctypes
import socket
import threading
import time
import os
import subprocess
import multiprocessing
#import pyopencl as cl
import numpy as np
from multiprocessing import Process
from pypresence import Presence
from ecdsa import SigningKey, SECP256k1
from tkterminal import Terminal



file_path = 'real.txt'
fallback_path = 'EMERGENCY.txt'
version = 'Version 1'



def DRPC():
    try:
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
    except:
        switch_var = 0


def send_webhook_message(data):
    response = requests.post(webhook_url, json=data)
    if response.status_code == 204:
        print('Webhook message sent successfully.')
    else:
        print('Failed to send webhook message.')
        print(data) #In case the webhook message fails the data which was supposed to be sent will be printed into the terminal as well as a TXT-File as a kind of "emergency fallback"
        with open(fallback_path, 'a+') as file:
            file.write(data)


def stoperrormessage():
    Process.kill(self=all)


def import_pubkeys(file_path):
    try:
        with open(file_path, 'rb') as file:
            contents = file.read()
            return contents.decode('utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.") 
        stoperrormessage()
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


btc = import_pubkeys(file_path)


def startMiner3():
    workerint = workervar.get()
    for i in range(workerint):
        miner = Miner()
        miner.start()


class Miner(threading.Thread):
    def __init__(self):
        super().__init__()
        self._stop_event = threading.Event()

    def run(self):
        start = int('000000000000000000000000000000000000000000000002c000000020449e9c', 16)
        end = int('000000000000000000000000000000000000000000000003ffffffffffffffff', 16)
        count = 1
        interval = 3600
        next_report_time = time.time() + interval
        try:
            while True:
                for i in range(start, end + 1):
                    puzzleaddr = "btc"
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
                            file.write(f"Address: {address} Hex-Key: {private_key_hex}")
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
        finally:
            print("Mining has stopped.")

    def get_id(self):
        if hasattr(self, '_thread_id'):
            return self._thread_id
        for id, thread in threading._active.items():
            if thread is self:
                return id

    def raise_exception(self):
        thread_id = self.get_id()
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(SystemExit))
        if res > 1:
            ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
            print('Exception raise failure')

def stop1():
    miner = Miner()
    miner.stop()
    miner.join()


def stop():
    miner = Miner()
    miner.raise_exception()
    miner.join()
    time.sleep(0.5)


customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("dark-blue")


app = customtkinter.CTk()
app.geometry("720x480")
app.title("Militarized Wallet Cracker")
app.iconbitmap('mwc.ico')


title = customtkinter.CTkLabel(app, text="Welcome to the Militarized Wallet Cracker!")
title.pack(padx=4, pady=4)


discord = customtkinter.CTkLabel(app, text="Join my Discord for Help: https://discord.agony.ch/")
discord.pack(padx=4, pady=4)


webhook = customtkinter.CTkLabel(app, text="Input your Webhook-URL and settings below, enjoy!")
webhook.pack(padx=4, pady=4)


versonstring = customtkinter.CTkLabel(app, text=version)
versonstring.pack(padx=4, pady=4)


workervar = tkinter.IntVar()
dunno2 = customtkinter.CTkEntry(app, width=40, height=40, textvariable=workervar)
dunno2.pack(padx=4, pady=4)


webhookvar = tkinter.StringVar()
aaaa = customtkinter.CTkEntry(app, width=240, height=40, textvariable=webhookvar)
aaaa.pack(padx=4, pady=4)


window_title = 'Militarized Wallet Cracker'
webhook_url = webhookvar
file_path = 'real.txt'


idfkanymore = customtkinter.CTkButton(app, text="Start Mining", command=startMiner3, fg_color="red")
idfkanymore.pack(padx=4, pady=4)


idfkanymore2 = customtkinter.CTkButton(app, text="Stop Mining", command=stop, fg_color="red")
idfkanymore2.pack()


switch_var = customtkinter.StringVar(value="on")
switch = customtkinter.CTkSwitch(app, text="Discord Rich Presence", command=DRPC(),
                                 variable=switch_var, onvalue="on", offvalue="off")
switch.pack(padx=4, pady=4)


if __name__ == '__main__':
    multiprocessing.freeze_support()
    app.mainloop()