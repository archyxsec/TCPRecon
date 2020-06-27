#!/usr/bin/python3

# This script runs on Python 3
import socket, threading, time
from pwn import *
from termcolor import colored
from argparse import ArgumentParser
import os

def parserargs():
   parser = ArgumentParser(description='%(prog)s is a port scanner')
   parser.add_argument('-i','--ip', help="ip to scan", type=str)
   return parser

def TCP_connect(ip, port_number, output):

    try:
        TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCPsock.settimeout(2)
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Listening'
#        print(port_number)
#        p.status("Port {} open".format(port_number))
    except:
        output[port_number] = ''
#        p.status("Port {} close".format(port_number))


def scan_ports(host_ip, delay):

    threads = []        # To run TCP_connect concurrently
    output = {}         # For printing purposes

    p = log.progress("Create threads")
    time.sleep(1)
    # Spawning threads to scan ports
    for i in range(10000):
        try:
            t = threading.Thread(target=TCP_connect, args=(host_ip, i, output))
            threads.append(t)
        except:
            pass

    p.success("All threads created")
    time.sleep(1)

    p = log.progress("Scanning all ports..")
    time.sleep(2)
    # Starting threads
    for i in range(10000):
        try:
            threads[i].start()
        except Exception:
            raise

    # Locking the main thread until all threads complete
    for i in range(10000):
       try:
           threads[i].join()
       except:
           pass

    p.success("All port have been scanned")
    time.sleep(1)
    print(colored("Show open ports..",'magenta'))
    print(colored("+-----+",'blue'))
    for port,status in output.items():
        if status == 'Listening':
            portdef = len(str(port))
            print(colored("|",'blue'),end = "")
            print(colored(port,'red'),end = "")
            diferencia = 7-2-portdef
            for i in range(1,diferencia+1):
                print(" ",end = "")
            print(colored("|",'blue'))
    print(colored("+-----+",'blue'))

def main():
    parser = parserargs()
    args = parser.parse_args()

    if args.ip == None:
        parser.print_help()
    else:
        scan_ports(args.ip,2)

try:
    main()
except:
	log.failure("Exiting..")

