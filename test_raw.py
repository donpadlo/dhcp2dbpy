#!/usr/bin/env python3
# coding=utf-8
# Сервер DHCP на Python 3.5 с коннектором к БД MySQL
# Данный код создан и распространяется по лицензии GPL v3
# Изначальный автор данного кода - Грибов Павел
# http://грибовы.рф

import socket
import dhcp_parse_packet
from pprint import pprint
import threading
import sys
from xml.dom import minidom
import mysql.connector
from mysql.connector import Error
import time 
from array import *

import ctypes
import binascii
import struct




class BPF(object):
	def __init__(self):
		self.SO_ATTACH_FILTER = 26
		self.SO_ACCEPTFILTER = 16

		# instruction classes
		self.BPF_LD  = 0x00
		self.BPF_JMP = 0x05
		self.BPF_RET = 0x06

		# ld/ldx fields
		self.BPF_W   = 0x00    # word(4 byte)
		self.BPF_H   = 0x08    # helf word(2 byte)
		self.BPF_B   = 0x10    # byte(1 byte)
		self.BPF_ABS = 0x20    # absolute address

		# alu/jmp fields
		self.BPF_JEQ = 0x10
		self.BPF_K   = 0x00

	def fill_sock_filter(self, code, jt, jf, k):
		return struct.pack('HBBI', code, jt, jf, k)

	def statement(self, code, k):
		return self.fill_sock_filter(code, 0, 0, k)

	def jump(self, code, jt, jf, k):
		return self.fill_sock_filter(code, jt, jf, k)


class BPF_DHCP(BPF):
	def __init__(self):
		super(BPF_DHCP, self).__init__()

	def set_dhcp_filter(self, sock):
		command_list = [
			# filter IPv4
			self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_H, 12),
			self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 5, 0x0800),

			# filter UDP
			self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_B, 23),
			self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 3, 0x11),

			# filter destination port 67
			self.statement(self.BPF_LD | self.BPF_ABS | self.BPF_H, 36),
			self.jump(self.BPF_JMP | self.BPF_JEQ | self.BPF_K, 0, 1, 67),

			# return
			self.statement(self.BPF_RET | self.BPF_K, 0xffffffff), # pass
			self.statement(self.BPF_RET | self.BPF_K, 0x00000000)  # reject
		]
		self.print_commands(command_list)
		commands = b''.join(command_list)
		buffers = ctypes.create_string_buffer(commands)
		fprog = struct.pack('HL', len(command_list), ctypes.addressof(buffers))
		sock.setsockopt(socket.SOL_SOCKET, self.SO_ACCEPTFILTER, fprog)

	def print_commands(self, command_list):
		print("like <tcpdump -dd ...>")
		for i in list(map(lambda x: binascii.hexlify(x).decode('ascii'), command_list)):
			print(i)



udp_socket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
BPF_DHCP().set_dhcp_filter(udp_socket)
udp_socket.bind(("0.0.0.0",67))
print("-wait packets..");
while True:
    data, addr = udp_socket.recvfrom(1024)
    print(addr);

# закончили работу       
udp_socket.close()
exit(0)
