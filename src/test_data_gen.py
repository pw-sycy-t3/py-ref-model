import json
import random
import socket
import struct

def ip_to_int(ip):
    """Konwersja adresu IP do 32-bitowej liczby calkowitej."""
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def hardware_hash_104b(src_ip, dst_ip, src_port, dst_port, proto, seed, num_bins):
    """
    Sprzetowa funkcja haszujaca (XOR-Fold). 
    W FPGA zrealizowana jako rownolegle drzewo bramek XOR.
    Koszt sprzetowy: < 100 LUTs, Opoznienie: 0 cykli zegara.
    """
    part1 = src_ip ^ seed
    part2 = dst_ip
    part3 = (src_port << 16) | dst_port
    part4 = proto
    
    # Mieszanie bitow - latwe do syntezy w Verilogu
    mixed = part1 ^ part2 ^ part3 ^ part4
    # Przesuniecie zapobiegajace kolizjom symetrycznym
    mixed ^= (mixed >> 16) 
    
    # Zwracamy indeks do pamieci BRAM/RAM
    return mixed % num_bins

RANDOM_SEED = 42


def generate_golden_dataset(num_hosts=10000, num_packets=5000):
    random.seed(RANDOM_SEED)
    print(f"[*] Generowanie bazy {num_hosts} zaufanych hostow (Sektor 7)...")
    authorized_rules = []
    
    # Generacja 10 000 autoryzowanych 5-krotek
    for _ in range(num_hosts):
        rule = {
            "src_ip": int_to_ip(random.randint(0x0A000000, 0x0AFFFFFF)), # Siec 10.x.x.x
            "dst_ip": "192.168.100.1", # Glowny serwer Cytadeli
            "src_port": random.randint(1024, 65535),
            "dst_port": 443, # Tylko HTTPS
            "proto": 6 # TCP
        }
        authorized_rules.append(rule)
        
    with open("files/aegis_rules.json", "w") as f:
        json.dump(authorized_rules, f, indent=4)
        
    print("[*] Zapisano plik aegis_rules.json")
    # TBD: Generacja ruchu testowego w kolejnym module...
