#! /usr/bin/env python

import sys
from collections import defaultdict
from types_dic import types_dic
from scapy.all import *
from math import exp, log

def fill_dict(dic, key):
    if key in dic:
        dic[key] += 1
    else:
        dic[key] = 1

def get_source(pkt):

    global pkt_sniffed_count
    global pkt_arp_count
    global obs_types_dic

    # Diccionario para guardar paquetes ARP encontrados
    global arp_dic
    
    # Identifico el tipo de capa 2 del paquete
    if 'type' in pkt.fields:
        
        # Cuento un paquete mas del type correspondiente para la fuente S
        fill_dict(obs_types_dic, str(hex(pkt.fields['type'])))
        
        # Cuento un paquete solo del type ARP para la fuente S_1
        type_str = str(hex(pkt.fields['type']))
        
        # Logueamos si encontramos un paquete de tipo desconocido para el dict
        if not type_str in types_dic:
            print type_str
        
        # Si el paquete es ARP de tipo who-has guardamos su ip destino
        elif types_dic[type_str] == "ARP" and pkt.op == 1:
            pkt.show()
            fill_dict(arp_dic, pkt.pdst)
            pkt_arp_count += 1
                
    # Caso especial 802.3
    elif 'len' in pkt.fields:
        fill_dict(obs_types_dic, "0xff0f")

    pkt_sniffed_count += 1

if __name__ == '__main__':

    # Tiempo que sniffeamos la red
    timeout = None
    count = 0

    # Estadisticas
    pkt_sniffed_count = 0
    entropia_s = 0
    entropia_s_1 = 0
    prob_tmp = 0
    pkt_arp_count = 0
   
    # dicc de tipos observados
    obs_types_dic = defaultdict(int)
    arp_dic = defaultdict(int)

    if len(sys.argv) == 3:
        # Si recibimos por parametro count contamos esa cantidad de paquetes
        if sys.argv[1] == 'count':
            count = int(sys.argv[2])
        # Si no, sniffeamos 1hs
        elif sys.argv[1] == 'time':
            timeout = int(sys.argv[2])

    # Sniff
    sniff(prn=get_source, store=0, count=count, timeout=timeout)
    logfile = open("data.log", "w")
    logfile.write("Paquetes vistos: " + str(pkt_sniffed_count) + "\n")
    logfile.write("\n")

    # probabilidad de la fuente S
    for key, value in obs_types_dic.iteritems():
        prob_tmp = value/float(pkt_sniffed_count)
        
        if not key in types_dic:
            logfile.write("Probabilidad de " + str(key) + ": " + str(prob_tmp) + "\n")
        else:
            logfile.write("Probabilidad de " + types_dic[key] + ": " + str(prob_tmp) + "\n")
            
        entropia_s += prob_tmp * (-log(prob_tmp,2))
            
    # entropia de la fuente S
    logfile.write("Entropia de S: " + str(entropia_s) + "\n\n")

    prob_tmp = 0

    logfile.write("Paquetes ARP vistos: " + str(pkt_arp_count) + "\n")
    logfile.write("\n")

    # probabilidad de la fuente S_1
    for key, value in arp_dic.iteritems():
        prob_tmp = value/float(pkt_arp_count)
        logfile.write("Probabilidad de " + str(key) + ": " + str(prob_tmp) + " - Paquetes: " + str(value) + "\n")
        entropia_s_1 += prob_tmp * (-log(prob_tmp,2))
    # entropia de la fuente S
    logfile.write("Entropia de S_1: " + str(entropia_s_1) + "\n\n")
    
    logfile.close()
