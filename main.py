import hashlib
import base58
import binascii
import requests
import socket
import time
import yaml
import os
import threading
import pyopencl as cl
import siphash24
#import numpy as np
#from multiprocessing import Process
from pypresence import Presence
from ecdsa import SigningKey, SECP256k1



window_title = 'Militarized Wallet Cracker'
webhook_url = 'https://discord.com/api/webhooks/1199070140738838549/b2-lCvbeHL0BhCqkwlVPoWPfvcjRNsMAfQW6tbDOcgXNO_jO23w_4lP85dFps4CtLcjQ'    # <-- Change this
file_path = 'real.txt'
version = 0.7



class DiscordRPC(threading.Thread):
    def __init__(self):
       super().__init__()
       self._stop_event = threading.Event()

    def run(self):
        client_id = "1199083933955018863"
        RPC = Presence(client_id)
        RPC.connect()
        RPC.update(state="Mining Crypto with MWC!" ,
            start = int(time.time()),
            large_text="Developed by 4G0NYY",
            large_image="mew" ,
            small_image="small2",
            small_text="hardtruth",
            buttons=[{"label": "GitHub", "url": "https://github.com/4G0NYY/MWC-Public"}, {"label": "Discord", "url": "https://discord.gg/gpt4k7jBbv"}])
        while not self._stop_event.is_set():
            time.sleep(15)
            continue
        RPC.close()

    def stop(self):
        self._stop_event.set()

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




def send_webhook_message(data):
    response = requests.post(webhook_url, json=data)
    if response.status_code == 204:
        print('Webhook message sent successfully.')
    else:
        print('Failed to send webhook message.')


def read_yaml():
    try:
        with open('config.yaml') as f:
            data = yaml.load(f, Loader=yaml.FullLoader)
            use_config = data['USE_CONFIG']

            if use_config == True:
                    return True
            else:
                    return False
    except:
        pass


def importconfig():
    with open('config.yaml') as f:
        data = yaml.load(f,Loader=yaml.FullLoader)
        address = data['ADDRESS']
        bad_log = data['BAD_HIT_LOG']
        webhook = data['DISCORD_WEBHOOK']
        workers = data['WORKERS']

        return address,workers,bad_log,webhook


def import_pubkeys(file_path):
    try:
        with open(file_path, 'rb') as file:
            contents = file.read()
            return contents.decode('utf-8', errors='ignore')
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        print("The file with all the addresses cannot be found. Did you place it in the correct directory?")
        if True:
            error = 1
            return error
    except Exception as e:
        print(f"An error occurred: {e}")
        return None
    return error

btc = import_pubkeys(file_path)

class MinerGPU():
    def MinerGPU(start, end):
        def Miner_GPU(a):
            ctx = cl.create_some_context()
            queue = cl.CommandQueue(ctx)
            mf = cl.mem_flags
            a_buf = cl.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=a)
            count = 1
            interval = 3600
            next_report_time = time.time() + interval

            if os.path.exists('progress.txt'):
                with open('progress.txt', 'r') as file:
                    last_checked_key = int(file.read().strip(), 16)
                    print(f'Resuming from key: {hex(last_checked_key)}')
            else:
                last_checked_key = start
                print('Starting from the beginning.')

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
                if count % (interval * 10) == 0:
                    with open('progress.txt', 'w') as file:
                        file.write(hex(i))
                prg = cl.Program(ctx, """
                    __kernel void add(__global float* a) {
                        int i = get_global_id(0);
                        a[i] += 1;
                    }
                """).build()
            prg.add(queue, a.shape, None, a_buf)
            cl.enqueue_copy(queue, a, a_buf).wait()



a = """ 
     .----------------.  .----------------.  .----------------. 
    | .--------------. || .--------------. || .--------------. |
    | | ____    ____ | || | _____  _____ | || |     ______   | |
    | ||_   \  /   _|| || ||_   _||_   _|| || |   .' ___  |  | |
    | |  |   \/   |  | || |  | | /\ | |  | || |  / .'   \_|  | |
    | |  | |\  /| |  | || |  | |/  \| |  | || |  | |         | |
    | | _| |_\/_| |_ | || |  |   /\   |  | || |  \ `.___.'\  | |
    | ||_____||_____|| || |  |__/  \__|  | || |   `._____.'  | |
    | |              | || |              | || |              | |
    | '--------------' || '--------------' || '--------------' |
     '----------------'  '----------------'  '----------------' 

                      Militarized Wallet Cracker                                                                             
"""

b = """
Welcome to the Militarized Wallet Cracker!
This tool is for educational purposes only ;)
This Software is FREE, if you payed for it, you got scammed.
Join my Discord for Help: https://discord.gg/gpt4k7jBbv
"""

def intro():
    print(version)
    print(a)
    print(b)


if __name__ == '__main__':

    intro()
    MinuteGPU = input("Do you wish to use GPU-Accelerated Computing? (y/n)")
    if MinuteGPU == "y":
        try:
            presence_thread = DiscordRPC()
            presence_thread.start()
            num_workers = input("How many workers would you like to spawn?")
            workerint = int(num_workers)

            for i in range(workerint):
                MinerGPU.thread = MinerGPU()
                MinerGPU.thread.start()
        except Exception as e:
            if "Discord" in str(e):
                for i in range(workerint):
                    MinerGPU.thread = MinerGPU()
                    MinerGPU.start()
        else:
            print("Debugger: An Error occurred during code execution. Printing Error...\n")
            input("")
            exit()
    else:
        try:
            presence_thread = DiscordRPC()
            presence_thread.start()
            num_workers = input("How many workers would you like to spawn? ")
            workerint = int(num_workers)

            for i in range(workerint):
                miner_thread = Miner()
                miner_thread.start()
        except Exception as e:
            if "Discord" in str(e):
                num_workers = input("How many workers would you like to spawn? ")
                workerint = int(num_workers)
                for i in range(workerint):
                    miner_thread = Miner()
                    miner_thread.start()
            else:
                print("Debugger: An Error occurred during code execution. Printing Error...\n")
                print(e)
                input("")
                exit()