# coding=utf-8
# Сервер DHCP на Python 3.5 с коннектором к БД MySQL
# Данный код создан и распространяется по лицензии GPL v3
# Изначальный автор данного кода - Грибов Павел
# http://грибовы.рф

import socket
from struct import *
from pprint import pprint
import mysql.connector
from mysql.connector import Error

gconfig={}
gconfig["debug"]=False

# парсим входящий пакет
def parsepacketIn(data,cnf,optionsMod): 
 global gconfig
 gconfig=cnf #устанавливаем признак DEBUG
 try:
    if gconfig["debug"]==True:print("Len data:",len(data))
    op="unknown"
    if data[0]==1: op="DHCPDISCOVER/DHCPREQUEST";
    if data[0]==2: op="DHCPOFFER/DHCPACK";    
    if data[1]==1: htype="MAC" 
    else : htype="unknown"    
    hlen=data[2]
    hops=data[3]
    xidhex=data[4:8].hex()
    xidbyte=data[4:8]
    secs=data[8]*256+data[9];
    flags=pack('BB',data[10],data[11])
    ciaddr=socket.inet_ntoa(pack('BBBB',data[12],data[13],data[14],data[15]));    
    yiaddr=socket.inet_ntoa(pack('BBBB',data[16],data[17],data[18],data[19]));    
    siaddr=socket.inet_ntoa(pack('BBBB',data[20],data[21],data[22],data[23]));   
    giaddr=socket.inet_ntoa(pack('BBBB',data[24],data[25],data[26],data[27]));   
    chaddr=data[28:34].hex()
    magic_cookie=data[236:240]    
    if gconfig["debug"]==True:print("Magic:",magic_cookie[0],magic_cookie[1],magic_cookie[2],magic_cookie[3])
    res={"op":op,"htype":htype,"hlen":hlen,"hops":hops,"xidbyte":xidbyte,"xidhex":xidhex,"secs":secs,"flags":flags,"ciaddr":ciaddr,"yiaddr":yiaddr,"siaddr":siaddr,"giaddr":giaddr,"chaddr":chaddr,"magic_cookie":magic_cookie}        
    res["HostName"]="unknown";
    res["ClientMacAddress"]=chaddr;
    res["ClientMacAddressByte"]=data[28:34];
    res["RequestedIpAddress"]="0.0.0.0";
    res["option82"]="none";
    if magic_cookie==b'c\x82Sc':                
        # парсим опции
        if gconfig["debug"]==True:print("--парсим опции");
        options=data[240:len(data)]
        if gconfig["debug"]==True:print("Options:",options);        
        res["gpoz"]=240;
        while res["gpoz"]<len(data):
            if gconfig["debug"]==True:print("Option:",data[res["gpoz"]]," hex",hex(data[res["gpoz"]])[2:], "Len:",data[res["gpoz"]+1])
            res=FindOptions(data,res)            
        res["result"]=True
    else:    
        res["result"]=False        
 except IndexError:
    res["result"]=False
 #ну и на последок, подставим модификаторы..
 for option in optionsMod:
   spoption=option.split(":")
   if spoption[0] in res:
    res[spoption[1]]=res[spoption[0]][int(spoption[2]):int(spoption[3])]
 # 
 return res

# находим опции в пакете
def FindOptions(data,res):
    #Тип запроса
    if data[res["gpoz"]]==53: 
        res["option53"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]
        if data[res["gpoz"]+2]==1: res["op"]="DHCPDISCOVER"
        if data[res["gpoz"]+2]==3: res["op"]="DHCPREQUEST"
        if data[res["gpoz"]+2]==2: res["op"]="DHCPOFFER"
        if data[res["gpoz"]+2]==4: res["op"]="DHCPOFFER"
        if data[res["gpoz"]+2]==5: res["op"]="DHCPACK"
        if data[res["gpoz"]+2]==8: res["op"]="DHCPINFORM"
        res["gpoz"]=res["gpoz"]+ln+2;
        return res
    #MAC address клиента
    if data[res["gpoz"]]==61:                 
        res["option61"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]
        htype=data[res["gpoz"]+2]
        res["HType"]="unknown";
        if htype==1:res["HType"]="Ethernet";        
        res["ClientMacAddress"]=data[res["gpoz"]+3:res["gpoz"]+2+ln].hex()
        res["ClientMacAddressByte"]=data[res["gpoz"]+3:res["gpoz"]+2+ln]
        res["gpoz"]=res["gpoz"]+ln+2;
        return res
    #DHCP Auto
    if data[res["gpoz"]]==116:                 
        res["option116"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]
        res["DHCPAUTO"]=True;
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    #HostName - имя железки
    if data[res["gpoz"]]==12:                 
        res["option12"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]
        res["HostName"]=data[res["gpoz"]+2:res["gpoz"]+ln+2]        
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    #Vendor - производитель
    if data[res["gpoz"]]==60:                 
        res["option60"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]
        res["Vendor"]=data[res["gpoz"]+2:res["gpoz"]+ln+2]
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    #Request List - список чего запрашивает железка
    if data[res["gpoz"]]==55:                 
        res["option55"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]
        preq=0;
        while preq<ln:
            if data[res["gpoz"]+2+preq]==1:res["ReqListSubnetMask"]=True;
            if data[res["gpoz"]+2+preq]==15:res["ReqListDomainName"]=True;
            if data[res["gpoz"]+2+preq]==3:res["ReqListRouter"]=True;
            if data[res["gpoz"]+2+preq]==6:res["ReqListDNS"]=True;
            if data[res["gpoz"]+2+preq]==31:res["ReqListPerfowmRouterDiscover"]=True;
            if data[res["gpoz"]+2+preq]==33:res["ReqListStaticRoute"]=True;
            if data[res["gpoz"]+2+preq]==43:res["ReqListVendorSpecInfo"]=43;
            preq=preq+1        
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # Запрошенный IP адрес
    if data[res["gpoz"]]==50:                 
        res["option50"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["RequestedIpAddress"]=socket.inet_ntoa(pack('BBBB',data[res["gpoz"]+2],data[res["gpoz"]+3],data[res["gpoz"]+4],data[res["gpoz"]+5]));    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # IP DHCP сервера
    if data[res["gpoz"]]==54:                 
        res["option54"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["DHCPServerIP"]=socket.inet_ntoa(pack('BBBB',data[res["gpoz"]+2],data[res["gpoz"]+3],data[res["gpoz"]+4],data[res["gpoz"]+5]));    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # IP Lease Time
    if data[res["gpoz"]]==51:                 
        res["option51"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["DHCPLeaseTime"]=data[res["gpoz"]+2]*256*256*256*256+data[res["gpoz"]+3]*256*256+data[res["gpoz"]+4]*256+data[res["gpoz"]+5];    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # Subnet Mask
    if data[res["gpoz"]]==1:                 
        res["option1"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["SubnetMask"]=socket.inet_ntoa(pack('BBBB',data[res["gpoz"]+2],data[res["gpoz"]+3],data[res["gpoz"]+4],data[res["gpoz"]+5]));    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # Router
    if data[res["gpoz"]]==3:                 
        res["option3"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["Router"]=socket.inet_ntoa(pack('BBBB',data[res["gpoz"]+2],data[res["gpoz"]+3],data[res["gpoz"]+4],data[res["gpoz"]+5]));    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # DNS
    if data[res["gpoz"]]==6:                 
        res["option6"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["DNS"]=socket.inet_ntoa(pack('BBBB',data[res["gpoz"]+2],data[res["gpoz"]+3],data[res["gpoz"]+4],data[res["gpoz"]+5]));    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # NTPS сервер времени
    if data[res["gpoz"]]==42:                 
        res["option42"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["NTPS"]=socket.inet_ntoa(pack('BBBB',data[res["gpoz"]+2],data[res["gpoz"]+3],data[res["gpoz"]+4],data[res["gpoz"]+5]));    
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res
    # Option82
    if data[res["gpoz"]]==82:                 
        res["option82"]=data[res["gpoz"]];
        ln=data[res["gpoz"]+1]        
        res["option_82_len"]=ln
        res["option_82_byte"]=data[res["gpoz"]+1:res["gpoz"]+2+ln];
        res["option_82_hex"]=data[res["gpoz"]+1:res["gpoz"]+2+ln].hex()
        res["option_82_str"]=str(data[res["gpoz"]+1:res["gpoz"]+2+ln])
        res["gpoz"]=res["gpoz"]+ln+2;                          
        return res    
    # финита ля комедиа
    if data[res["gpoz"]]==255:   
        res["gpoz"]=len(data)+1
        return res
    #не известная опция
    opname=str(data[res["gpoz"]])    
    ln=data[res["gpoz"]+1]
    if gconfig["debug"]==True:
        print("-не известная опция "+opname+" смещение ",ln);
        print(data[res["gpoz"]+1:res["gpoz"]+2+ln])
    res["unknown_option_"+opname]=data[res["gpoz"]+1:res["gpoz"]+2+ln]
    res["unknown_option_"+opname+"_hex"]=data[res["gpoz"]+1:res["gpoz"]+2+ln].hex()
    res["unknown_option_"+opname+"_str"]=str(data[res["gpoz"]+1:res["gpoz"]+2+ln])
    res["unknown_option_"+opname+"_len"]=ln    
    res["gpoz"]=res["gpoz"]+ln+2
    return res
def padding0(cnt):
    res=b''
    pz=0
    while pz<cnt:        
        res=res+pack("B",0)
        pz=pz+1
    return res    
# Собираем предложение DHCPOFFER
def CreateDHCPOFFER(packet,res_sql):
    if gconfig["debug"]==True: print("---собираемся отвечать..")
    print ("--делаем ему DHCPOFFER",res_sql["ip"])
    pprint(gconfig["dhcp_Server"])    
    res=pack("B",2)     # тип ответа 
    res=res+pack("B",1) # тип железа Ethernet
    res=res+pack("B",6) # длина мас адреса
    res=res+pack("B",0) # количество шагов
    res=res+pack("BBBB",packet["xidbyte"][0],packet["xidbyte"][1],packet["xidbyte"][2],packet["xidbyte"][3]) # идентификатор посылки
    res=res+pack("BB",0,0) # сколько времени прошло?
    res=res+pack("BB",0,0) # флаги
    res=res+pack("BBBB",0,0,0,0) # кому отсылаем (всем) ciaddr
    res=res+socket.inet_pton(socket.AF_INET, res_sql["ip"]) # какой IP предлагает yiaddr
    res=res+socket.inet_pton(socket.AF_INET, "0.0.0.0") # siaddr
    res=res+socket.inet_pton(socket.AF_INET,packet["giaddr"]) # какой Relay
    res=res+pack("BBBBBB",packet["ClientMacAddressByte"][0],packet["ClientMacAddressByte"][1],packet["ClientMacAddressByte"][2],packet["ClientMacAddressByte"][3],packet["ClientMacAddressByte"][4],packet["ClientMacAddressByte"][5]) # MAC получателя
    res=res+padding0(202);
    res=res+packet["magic_cookie"]; # магическое число
    ##### ОПЦИИ ####################
    res=res+pack("BBB",53,1,2) # 53 опция, обозначем, что это пакет OFFER (предложение)
    res=res+pack("BB",54,4) # 54 опция, кто дает адрес?
    res=res+socket.inet_pton(socket.AF_INET, gconfig["dhcp_Server"])
    res=res+pack("BB",51,4)+pack(">I",8600) # 51 опция, время жизни адреса
    res=res+pack("BB",1,4) # 1 опция Mask
    res=res+socket.inet_pton(socket.AF_INET, res_sql["mask"])
    res=res+pack("BB",3,4) # 3 опция Router
    res=res+socket.inet_pton(socket.AF_INET, res_sql["router"])
    res=res+pack("BB",6,4) # 6 опция DNS
    res=res+socket.inet_pton(socket.AF_INET, res_sql["DNS"])
    if packet["option82"]!="none":        
        res=res+pack("B",82)
        for bb in packet["option_82_byte"]:           
           res=res+pack("B",bb)
    res=res+pack("B",255) # END
    res=res+padding0(28);
    #print ("LEN:",len(res));
    return res
def CreateDHCPACK(packet,res_sql):
    if gconfig["debug"]==True:print("---собираемся отвечать..")
    res=pack("B",2)     # тип ответа 
    res=res+pack("B",1) # тип железа Ethernet
    res=res+pack("B",6) # длина мас адреса
    res=res+pack("B",0) # количество шагов
    res=res+pack("BBBB",packet["xidbyte"][0],packet["xidbyte"][1],packet["xidbyte"][2],packet["xidbyte"][3]) # идентификатор посылки
    res=res+pack("BB",0,0) # сколько времени прошло?
    res=res+pack("BB",0,0) # флаги
    res=res+pack("BBBB",0,0,0,0) # кому отсылаем (всем)
    res=res+socket.inet_pton(socket.AF_INET, res_sql["ip"]) # какой IP предлагает
    print ("--делаем ему DHCPACK",res_sql["ip"])
    res=res+socket.inet_pton(socket.AF_INET, gconfig["dhcp_Server"]) # какой IP у DHCP сервера
    res=res+socket.inet_pton(socket.AF_INET,packet["giaddr"]) # какой Relay
    res=res+pack("BBBBBB",packet["ClientMacAddressByte"][0],packet["ClientMacAddressByte"][1],packet["ClientMacAddressByte"][2],packet["ClientMacAddressByte"][3],packet["ClientMacAddressByte"][4],packet["ClientMacAddressByte"][5]) # MAC получателя
    res=res+padding0(202);
    res=res+packet["magic_cookie"]; # магическое число
    res=res+pack("BBB",53,1,5) # 53 опция, обозначем, что это пакет ACK (подтверждение)
    res=res+pack("BB",54,4) # 54 опция, кто дает адрес?
    res=res+socket.inet_pton(socket.AF_INET, gconfig["dhcp_Server"])
    res=res+pack("BB",51,4)+pack(">I",8600) # 51 опция, время жизни адреса
    res=res+pack("BB",1,4) # 1 опция Mask
    res=res+socket.inet_pton(socket.AF_INET, res_sql["mask"])
    res=res+pack("BB",3,4) # 1 опция Router
    res=res+socket.inet_pton(socket.AF_INET, res_sql["router"])
    res=res+pack("BB",6,4) # 6 опция DNS
    res=res+socket.inet_pton(socket.AF_INET, res_sql["DNS"])
    if packet["option82"]!="none":        
        res=res+pack("B",82)
        for bb in packet["option_82_byte"]:           
           res=res+pack("B",bb)    
    res=res+pack("B",255) # END
    res=res+padding0(28);    
    return res
    