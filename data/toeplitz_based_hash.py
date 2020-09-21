#!/usr/bin/env python
#-*- coding: utf-8 -*-
# Courtesy of https://gist.github.com/joongh/16867705b03b49e393cbf91da3cb42a7
# Test data including the secret key, ip, port numbers and the hash values
# as the result is from "Intel Ethernet Controller 710 Series Datasheet".

from __future__ import print_function

KEY=[]

def reset_key():
    global KEY
    KEY = [
        0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
        0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
        0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
        0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
        0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
         0x00, 0x00, 0x00, 0x00
    ]

def print_key():
    for k in KEY:
        print(bin(k)[2:].zfill(8))
    print('\n')

def left_most_32bits_of_key():
    return KEY[0] << 24 | KEY[1] << 16 | KEY[2] << 8 | KEY[3]

def shift_key():
    bitstr = ''
    for k in KEY:
       bitstr += bin(k)[2:].zfill(8)
    shifted = bitstr[1:]
    shifted += bitstr[0]
    for i, k in enumerate(KEY):
        KEY[i] = int(shifted[:8], 2)
        shifted = shifted[8:]

def compute_hash(input_bytes):
    reset_key()
    result = 0
    bitstr = ''
    for b in input_bytes:
        bitstr += bin(b)[2:].zfill(8) # eliminate prefix "0b" and fill zeros to fit into 8 bits
    for b in bitstr:
        if b == '1':
            result ^= left_most_32bits_of_key()
        shift_key()
    return result

def get_ip_number(ip):
    ip_num = ip.split('.')
    return int(ip_num[0]) << 24 | int(ip_num[1]) << 16 | int(ip_num[2]) << 8 | int(ip_num[3])

def get_input(src_ip, dst_ip, src_port, dst_port):
    src_ip_num = get_ip_number(src_ip)
    dst_ip_num = get_ip_number(dst_ip)
    input_bytes = []
    input_bytes.append((src_ip_num & 0xff000000) >> 24)
    input_bytes.append((src_ip_num & 0x00ff0000) >> 16)
    input_bytes.append((src_ip_num & 0x0000ff00) >> 8)
    input_bytes.append(src_ip_num & 0x000000ff)
    input_bytes.append((dst_ip_num & 0xff000000) >> 24)
    input_bytes.append((dst_ip_num & 0x00ff0000) >> 16)
    input_bytes.append((dst_ip_num & 0x0000ff00) >> 8)
    input_bytes.append(dst_ip_num & 0x000000ff)
    input_bytes.append((src_port & 0xff00) >> 8)
    input_bytes.append(src_port & 0x00ff)
    input_bytes.append((dst_port & 0xff00) >> 8)
    input_bytes.append(dst_port & 0x00ff)
    return input_bytes

example1 = ('66.9.149.187', '161.142.100.80', 2794, 1766)
example2 = ('199.92.111.2', '65.69.140.83', 14230, 4739)


if compute_hash(get_input(*example1)) == 0x51ccc178:
    print('example1: Hash OK')
else:
    print('example1: Hash NOT OK')

if compute_hash(get_input(*example2)) == 0xc626b0ea:
    print('example2: Hash OK')
else:
    print('example2: Hash NOT OK')
