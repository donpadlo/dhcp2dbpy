#!/usr/bin/env python3
# coding=utf-8
# Сервер DHCP на Python 3.5 с коннектором к БД MySQL
# Данный код создан и распространяется по лицензии GPL v3
# Изначальный автор данного кода - Грибов Павел
# http://грибовы.рф

from array import *
import dhcp_parse_packet
import mysql.connector
from mysql.connector import Error
from pprint import pprint
import socket
import sys
import threading
import time
from xml.dom import minidom

# основные настройки DHCP сервера
gconfig = {}
gconfig["debug"] = False
gconfig["config_file"] = ""

# модификаторы
optionsMod = []

# парсим файл с настройками
def ParseConfigXML():
    global gconfig    
    if gconfig["debug"] == True:print("-читаю файл настроек:", gconfig["config_file"])
    tree = minidom.parse(gconfig["config_file"])
    mconfig = tree.getElementsByTagName("mysql")
    for elem in mconfig:        
        gconfig["mysql_host"] = elem.getElementsByTagName("host")[0].firstChild.data      
        gconfig["mysql_username"] = elem.getElementsByTagName("username")[0].firstChild.data      
        gconfig["mysql_password"] = elem.getElementsByTagName("password")[0].firstChild.data      
        gconfig["mysql_basename"] = elem.getElementsByTagName("basename")[0].firstChild.data      
    dconfig = tree.getElementsByTagName("dhcpserver")
    for elem in dconfig:        
        gconfig["broadcast"] = elem.getElementsByTagName("broadcast")[0].firstChild.data      
        gconfig["dhcp_host"] = elem.getElementsByTagName("host")[0].firstChild.data      
        gconfig["dhcp_LeaseTime"] = elem.getElementsByTagName("LeaseTime")[0].firstChild.data      
        gconfig["dhcp_ThreadLimit"] = int(elem.getElementsByTagName("ThreadLimit")[0].firstChild.data)              
        gconfig["dhcp_Server"] = elem.getElementsByTagName("DHCPServer")[0].firstChild.data              
        gconfig["dhcp_defaultMask"] = elem.getElementsByTagName("defaultMask")[0].firstChild.data              
        gconfig["dhcp_defaultRouter"] = elem.getElementsByTagName("defaultRouter")[0].firstChild.data              
        gconfig["dhcp_defaultDNS"] = elem.getElementsByTagName("defaultDNS")[0].firstChild.data              
    qconfig = tree.getElementsByTagName("query")
    for elem in qconfig:  
        gconfig["offer_count"] = elem.getElementsByTagName("offer_count")[0].firstChild.data                          
        for num in range(int(gconfig["offer_count"])):
            gconfig["offer_" + str(num + 1)] = elem.getElementsByTagName("offer_" + str(num + 1))[0].firstChild.data      
        gconfig["history_sql"] = elem.getElementsByTagName("history_sql")[0].firstChild.data                          
    options = tree.getElementsByTagName("options")       
    for elem in options:          
        node = elem.getElementsByTagName("option")
        for options in node:
            optionsMod.append(options.firstChild.data)        
        
    if gconfig["debug"] == True:
        print("Настройки:")        
        pprint(gconfig)
        print("Дополнительные опции:")        
        pprint(optionsMod)
        
# смотрим параметры запуска скрипта
def ParamRunParse():
    gconfig["debug"]    
    if len(sys.argv) >= 2: 
        poz = 0
        while poz < len(sys.argv):            
            if sys.argv[poz] == "-d": gconfig["debug"] = True
            if sys.argv[poz] == "-c": gconfig["config_file"] = sys.argv[poz + 1]
            poz = poz + 1
        if gconfig["config_file"] == "":    
            print ("-не задан файл настроек")
            exit(1)         
    else:
        print ("Параметры запуска:")
        print ("  - d включить режим отладки")
        print ("  - c <файл.xml> имя файла настроек")
        exit(1)
# Ищем IP для выдачи
def GetSQLQuery(sql, packet, conn):
    global gconfig    
    res = {}
    #перебираем все переменные пакета
    for key in packet.keys():             
        sql = sql.replace("{" + key + "}", str(packet[key]))     
    if gconfig["debug"] == True:             
        print ("SQL:", sql)
    cursor = conn.cursor(dictionary=True, buffered=True)
    cursor.execute(sql);
    row = cursor.fetchone()	    
    res["ip"] = "";
    res["mask"] = gconfig["dhcp_defaultMask"]
    res["router"] = gconfig["dhcp_defaultRouter"]
    res["DNS"] = gconfig["dhcp_defaultDNS"]
    while row is not None:      
        res["ip"] = str(row["ip"], "ascii")
        res["mask"] = str(row["mask"], "ascii")
        res["router"] = str(row["router"], "ascii")
        res["DNS"] = str(row["dns"], "ascii")
        row = cursor.fetchone()
    if gconfig["debug"] == True:             
        print ("Результат:", res)         
    return res
def GetIp(packet, conn):
    res_sql = {}
    res_sql["ip"] = "";
    for num in range(int(gconfig["offer_count"])):
        if res_sql["ip"] == "": 
            res_sql = GetSQLQuery(gconfig["offer_" + str(num + 1)], packet, conn)
    return res_sql
# Вставляем в таблицу истории выдачи IP
def SQLInsert(sql, packet, conn):
    global gconfig    
        #перебираем все переменные пакета
    for key in packet.keys():             
        sql = sql.replace("{" + key + "}", str(packet[key]))     
    if gconfig["debug"] == True:             
        print ("SQL:", sql)
    cursor = conn.cursor(dictionary=True, buffered=True)
    cursor.execute(sql);
    conn.commit();
    return None
def PacketWork(data, addr): 
    global gconfig
    packet = dhcp_parse_packet.parsepacketIn(data, gconfig, optionsMod) # парсим содержимое пакета в читабельный вид
    if gconfig["debug"] == True: print("##################################################################################");
    print("--пришел пакет ", packet["op"], " на 67 порт,от ", packet["ClientMacAddress"], ",", packet["HostName"], ",", addr)
    if gconfig["debug"] == True:        
        pprint(packet)            
        pprint(addr)      
    try:
        conn = mysql.connector.connect(host=gconfig["mysql_host"], database=gconfig["mysql_basename"], user=gconfig["mysql_username"], password=gconfig["mysql_password"])
        if gconfig["debug"] == True and packet["op"] != "DHCPINFORM":  pprint(conn)                    
        # здесь соединение с MySQL уже есть..        
        if packet["op"] == "DHCPINFORM":        
            #просто запишем для истории 
            res_sql_ins = SQLInsert(gconfig["history_sql"], packet, conn)
        if packet["op"] == "DHCPDISCOVER":                     
            #пробуем полуить IP из базы 
            res_sql = GetIp(packet, conn)           
            if res_sql["ip"] != "":
                if gconfig["debug"] == True:print("--широковещательный поиск DHCP сервера...");
                packetoffer = dhcp_parse_packet.CreateDHCPOFFER(packet, res_sql)        
                if gconfig["debug"] == True: 
                    pprint(packetoffer)
                    pprint(dhcp_parse_packet.parsepacketIn(packetoffer, gconfig, optionsMod))
                #сначала бродкаст                      
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                rz = udp_socket.sendto(packetoffer, (gconfig["broadcast"], 68))
                if gconfig["debug"] == True:print("-ответили DHCPOFFER (предложение)!");
                #а если есть получатель, то  и конкретно ему..
                if packet["giaddr"] != "0.0.0.0":
                    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    #udp_socket.setsockopt(socket.SOL_SOCKET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    rz = udp_socket.sendto(packetoffer, addr)        
                res_sql_ins = SQLInsert(gconfig["history_sql"], packet, conn)
                    
            else:        
                print ("-- IP не нашли в БД, предлагать нечего..");                    
        if packet["op"] == "DHCPREQUEST":        
            #пробуем полуить IP из базы 
            res_sql = GetIp(packet, conn)           
            if res_sql["ip"] != "":                
                #пробуем полуить IP из базы 
                res_sql = GetIp(packet, conn)           
                if gconfig["debug"] == True:
                    print ("-- (DHCPREQUEST) устройство запросило у меня IP адрес....");
                    print (packet["RequestedIpAddress"])
                packetack = dhcp_parse_packet.CreateDHCPACK(packet, res_sql)
                if gconfig["debug"] == True:
                    pprint(packetack)
                    pprint(dhcp_parse_packet.parsepacketIn(packetack, gconfig, optionsMod))
                    print ("-- (DHCPACK) ответил ему бродкастом....");
                #сначала бродкаст 
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                rz = udp_socket.sendto(packetack, (gconfig["broadcast"], 68))        
                #а если есть получатель, то  и конкретно ему..
                if packet["giaddr"] != "0.0.0.0":
                    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    #udp_socket.setsockopt(socket.SOL_SOCKET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                    rz = udp_socket.sendto(packetack, addr)        
                res_sql_ins = SQLInsert(gconfig["history_sql"], packet, conn)
            else:        
                print ("-- IP не нашли в БД, отвечать нечего ..");                    
                    
    except Error as e:
        print("Ошибка установки соединения с MySQL: ", e);
        exit(0);    
    finally:               
        conn = None
    
# смотрим параметры запуска
ParamRunParse()
# парсим файл с настройками
ParseConfigXML()

print ("-DHCP сервер стартовал ", gconfig["dhcp_host"], ",потоков ", gconfig["dhcp_ThreadLimit"])        
udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
udp_socket.bind((gconfig["dhcp_host"], 67))

while True:
    data, addr = udp_socket.recvfrom(1024)
    if gconfig["debug"] == True:print ("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Новый UDP пакет пришел !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")    
    thread = threading.Thread(target=PacketWork, args=(data, addr, )).start()	
    while threading.active_count() > gconfig["dhcp_ThreadLimit"]:
       time.sleep(1)           

# закончили работу       
udp_socket.close()
exit(0)
