# Imports
import json
import socket  
import ipaddress  
import re  
import sys  
import os
import subprocess
from datetime import datetime
import time
from netaddr import IPNetwork, cidr_merge
import asyncio
from termcolor import colored
import yaml  
import emoji
import concurrent.futures  
import requests  
import mysql.connector  

#*#########*#
#? SETTINGS #
#*#########*#
#SOURCE_IP = "192.168.68.72" # Joost home
SOURCE_IP = "145.100.181.111" # SURF AS1101 debian

#*##########*#
#? FUNCTIONS #
#*##########*#

banner = """
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡠⢤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡴⠟⠃⠀⠀⠙⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠋⠀⠀⠀⠀⠀⠀⠘⣆⠀⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠾⢛⠒⠀⠀⠀⠀⠀⠀⠀⢸⡆⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣶⣄⡈⠓⢄⠠⡀⠀⠀⠀⣄⣷⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣷⠀⠈⠱⡄⠑⣌⠆⠀⠀⡜⢻⠀⠀⠀⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡿⠳⡆⠐⢿⣆⠈⢿⠀⠀⡇⠘⡆⠀⠀⠀⠀⠀⠀  
ORCESTRATOR VERSION 0.1⠀ ⠀⠀⠀⠀⢿⣿⣷⡇⠀⠀⠈⢆⠈⠆⢸⠀⠀⢣⠀⠀⠀⠀⠀⠀  
Scans 8 million ip's daily⠀ ⠀⠀ ⠘⣿⣿⣿⣧⠀⠀⠈⢂⠀⡇⠀⠀⢨⠓⣄⠀⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣦⣤⠖⡏⡸⠀⣀⡴⠋⠀⠈⠢⡀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣾⠁⣹⣿⣿⣿⣷⣾⠽⠖⠊⢹⣀⠄⠀⠀⠀⠈⢣⡀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡟⣇⣰⢫⢻⢉⠉⠀⣿⡆⠀⠀⡸⡏⠀⠀⠀⠀⠀⠀⢇  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢨⡇⡇⠈⢸⢸⢸⠀⠀⡇⡇⠀⠀⠁⠻⡄⡠⠂⠀⠀⠀⠘  
⢤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⠛⠓⡇⠀⠸⡆⢸⠀⢠⣿⠀⠀⠀⠀⣰⣿⣵⡆⠀⠀⠀⠀  
⠈⢻⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡿⣦⣀⡇⠀⢧⡇⠀⠀⢺⡟⠀⠀⠀⢰⠉⣰⠟⠊⣠⠂⠀⡸  
⠀⠀⢻⣿⣿⣷⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⢧⡙⠺⠿⡇⠀⠘⠇⠀⠀⢸⣧⠀⠀⢠⠃⣾⣌⠉⠩⠭⠍⣉⡇  
⠀⠀⠀⠻⣿⣿⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣞⣋⠀⠈⠀⡳⣧⠀⠀⠀⠀⠀⢸⡏⠀⠀⡞⢰⠉⠉⠉⠉⠉⠓⢻⠃  
⠀⠀⠀⠀⠹⣿⣿⣿⣿⣿⣿⣷⡄⠀⠀⢀⣀⠠⠤⣤⣤⠤⠞⠓⢠⠈⡆⠀⢣⣸⣾⠆⠀⠀⠀⠀⠀⢀⣀⡼⠁⡿⠈⣉⣉⣒⡒⠢⡼⠀  
⠀⠀⠀⠀⠀⠘⣿⣿⣿⣿⣿⣿⣿⣎⣽⣶⣤⡶⢋⣤⠃⣠⡦⢀⡼⢦⣾⡤⠚⣟⣁⣀⣀⣀⣀⠀⣀⣈⣀⣠⣾⣅⠀⠑⠂⠤⠌⣩⡇⠀  
⠀⠀⠀⠀⠀⠀⠘⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡁⣺⢁⣞⣉⡴⠟⡀⠀⠀⠀⠁⠸⡅⠀⠈⢷⠈⠏⠙⠀⢹⡛⠀⢉⠀⠀⠀⣀⣀⣼⡇⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⣿⣿⣿⣿⣿⣿⣽⣿⡟⢡⠖⣡⡴⠂⣀⣀⣀⣰⣁⣀⣀⣸⠀⠀⠀⠀⠈⠁⠀⠀⠈⠀⣠⠜⠋⣠⠁⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢿⣿⣿⣿⡟⢿⣿⣿⣷⡟⢋⣥⣖⣉⠀⠈⢁⡀⠤⠚⠿⣷⡦⢀⣠⣀⠢⣄⣀⡠⠔⠋⠁⠀⣼⠃⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣿⡄⠈⠻⣿⣿⢿⣛⣩⠤⠒⠉⠁⠀⠀⠀⠀⠀⠉⠒⢤⡀⠉⠁⠀⠀⠀⠀⠀⢀⡿⠀⠀⠀  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣤⣤⠴⠟⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠤⠀⠀⠀⠀⠀⢩⠇ 
                        
"""
def asciiart():
    orc_lines = banner.split("\n")
    version_color = "yellow"
    hacker_color = "green"
    print("")
    for line in orc_lines:
        if line.find("ORCESTRATOR VERSION 0.1") != -1:
            line = line.replace("ORCESTRATOR VERSION 0.1", colored("ORCESTRATOR VERSION 0.1", version_color, attrs=['bold']))
        if line.find("⢿⣿⣷⡇⠀⠀⠈⢆⠈⠆⢸⠀⠀⢣"):
            line = line.replace("⢿⣿⣷⡇⠀⠀⠈⢆⠈⠆⢸⠀⠀⢣", colored("⢿⣿⣷⡇⠀⠀⠈⢆⠈⠆⢸⠀⠀⢣",hacker_color))
        print(colored(line, hacker_color))

def yaml_to_dict(yaml_content: str) -> dict:  
    return yaml.safe_load(yaml_content)  

def helpmenu():
    print("Usage: python preprocess.py <input_file.txt> [exclude_file.txt] [exclude_port_file.txt]")
    print("")
    print("Input file is required, exclude file and exclude port file are optional")
    print("The input file is a list of ip's, cidr's or domains to scan with masscan")
    print("The exclude file is a list of ip's, cidr's or domains to exclude from the scan")
    print("The exclude port file is a list of domain/ip/cidr:port to exclude from the scan")
    print("")
    print("Input file format:")
    print("list of ip's, cidr's or domains, one per line")
    print("examples: 192.168.1.1, 192.168.1.0/24, example.com, www.example.com, https://www.example.com")
    print("")
    print("Exclude file format:")
    print("list of ip's, cidr's or domains, one per line")
    print("examples: 192.168.1.1, 192.168.1.0/24, example.com, www.example.com, https://www.example.com")
    print("")
    print("Exclude port file format:")
    print("list of domain/ip/cidr:port, one per line")
    print("examples: 192.168.1.1:21, 192.168.1.0/24:22, example.com:443, www.example.com:80, https://www.example.com:8080")
    print("")
    print("Happy scannng :)")

def print_finding(category, url, severity, specific, subspecific, endmessage="", confidence=""):
    severity = severity.lower()
    severity_color = 'blue'
    if severity == 'low':
        severity_color = 'green'
    elif severity == 'medium':
        severity_color = 'yellow'
    elif severity == 'high':
        severity_color = 'red'

    # create string
    outputstring = "[" + specific + ":" +  subspecific + "] " + "[" + category + "]" + " [" + severity + "] "

    # possible additions
    if endmessage != "":
        outputstring = outputstring + "[" + endmessage + "] "
    if confidence != "":
        outputstring = outputstring + "Confidence: " + confidence + "% "

    outputstring = outputstring.replace("[", colored("[", "white"))
    outputstring = outputstring.replace("]", colored("]", "white"))
    outputstring = outputstring.replace("low", colored("low" + emoji.emojize(":locked_with_key:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("medium", colored("medium" + emoji.emojize(":warning:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("high", colored("high" + emoji.emojize(":red_exclamation_mark:"), severity_color, attrs=['bold']))
    outputstring = outputstring.replace("info", colored("info", severity_color, attrs=['bold'])) #replace with emoji
    outputstring = outputstring.replace(category, colored(category, "blue"))
    outputstring = outputstring.replace(specific, colored(specific, "green"))
    outputstring = outputstring.replace(subspecific, colored(subspecific, "green", attrs=['bold']))

    if confidence != "":
        outputstring = outputstring.replace("Confidence: ", colored("Confidence: ", "green", attrs=['bold']))
        if int(confidence) > 70:
            outputstring = outputstring.replace(confidence + "%", colored(confidence + "%", "green"))
        elif int(confidence) > 40:
            outputstring = outputstring.replace(confidence + "%", colored(confidence + "%", "yellow", attrs=['bold']))
        else:
            outputstring = outputstring.replace(confidence + "%", colored(confidence + "%", "red", attrs=['bold']))

    if endmessage != "":
        outputstring = outputstring.replace("[" + endmessage + "]", colored("[" + endmessage + "]", "magenta"))

    # add url
    outputstring = outputstring + url
    outputstring = outputstring.replace(url, colored(url, "white"))


    # ADD verified check at end if verified

    print(colored(outputstring, "white"))
    
def is_ip(ip):
    """
    Determines whether the given string is a valid IP address.

    Args:
        ip (str): The string to check.

    Returns:
        bool: True if the string is a valid IP address, False otherwise.

    Examples:
        >>> is_ip('192.168.0.1')
        True
        >>> is_ip('256.256.256.256')
        False
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_ip_port(ip):
    """
    Determines whether the given string is a valid IP address with a port.

    Args:
        ip (str): The string to check.

    Returns:
        bool: True if the string is a valid IP address with a port, False otherwise.

    Examples:
        >>> is_ip_port('192.168.0.1:8080')
        True
        >>> is_ip_port('256.256.256.256:80')
        False
        >>> is_ip_port('192.168.0.1')
        False
    """
    try:
        # split on last : only to allow ipv6 addresses
        ip_port = ip.rsplit(':', 1)
        if len(ip_port) != 2:
            return False

        # checking if first part is ip
        ipaddress.ip_address(ip_port[0])

        # checking if second part is port
        if not ip_port[1].isdigit():
            return False

        return True
    except ValueError:
        return False

def is_cidr(cidr):
    """
    Determines whether the given string is a valid CIDR notation.

    Args:
        cidr (str): The string to check.

    Returns:
        bool: True if the string is a valid CIDR notation, False otherwise.

    Examples:
        >>> is_cidr('192.168.0.0/24')
        True
        >>> is_cidr('2001:db8::/32')
        True
        >>> is_cidr('192.168.0.0/33')
        False
        >>> is_cidr('2001:db8::/129')
        False
        >>> is_cidr('192.168.0.0')
        False
    """
    try:
        ip_net = ipaddress.ip_network(cidr, strict=False)
        if ip_net.version == 4:
            return ip_net.prefixlen < 32
        elif ip_net.version == 6:
            return ip_net.prefixlen < 128
    except ValueError:
        return False

def is_cidr_port(cidr):
    """
    Determines whether the given string is a valid CIDR notation with a port number.

    Args:
        cidr (str): The string to check.

    Returns:
        bool: True if the string is a valid CIDR notation with a port number, False otherwise.

    Examples:
        >>> is_cidr_port('192.168.0.0/24:80')
        True
        >>> is_cidr_port('2001:db8::/32:443')
        True
        >>> is_cidr_port('192.168.0.0/33:8080')
        False
        >>> is_cidr_port('2001:db8::/129:22')
        False
        >>> is_cidr_port('192.168.0.0')
        False
    """
    try:
        # splitting the CIDR and port number
        cidr_port = cidr.rsplit(':', 1)

        if len(cidr_port) != 2:
            return False

        # checking if the first part is a valid CIDR notation
        ip_net = ipaddress.ip_network(cidr_port[0], strict=False)

        # checking if the second part is a valid port number
        if not cidr_port[1].isdigit():
            return False

        # checking if the CIDR notation is valid for the IP version
        if ip_net.version == 4:
            return ip_net.prefixlen < 32
        elif ip_net.version == 6:
            return ip_net.prefixlen < 128
    except ValueError:
        return False

def hostname_to_ip(hostname):
    """
    Resolves the IP address of a given hostname.

    Args:
        hostname (str): The hostname to resolve.

    Returns:
        str: The IP address of the given hostname, or None if the hostname cannot be resolved.

    Examples:
        >>> hostname_to_ip('www.google.com')
        '172.217.7.196'
        >>> hostname_to_ip('invalidhostname')
        None
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def extract_hostname(url):  
    """
    Extracts the hostname from a given URL.

    Args:
        url (str): The URL to extract the hostname from.

    Returns:
        str: The hostname of the given URL, or None if the hostname cannot be extracted.

    Examples:
        >>> extract_hostname('https://www.google.com/search?q=python')
        'www.google.com'
        >>> extract_hostname('invalidurl')
        None
    """
    pattern = r'(?:https?://)?(?:www\.)?([^:/?]+)'
    return match[1] if (match := re.search(pattern, url)) else None   

def extract_hostname_port(url_port):  
    """
    Extracts the hostname and port from a given URL with port.

    Args:
        url_port (str): The URL with port to extract the hostname and port from.

    Returns:
        str: The hostname and port of the given URL with port, or None if the hostname and port cannot be extracted.

    Examples:
        >>> extract_hostname_port('https://www.google.com:8080/search?q=python')
        'www.google.com:8080'
        >>> extract_hostname_port('https://www.google.com/search?q=python')
        'www.google.com'
        >>> extract_hostname_port('invalidurl')
        None
    """
    pattern = r'(?:https?://)?(?:www\.)?([^:/?]+)(?::(\d+))?'  
    match = re.search(pattern, url_port)  
    if match:  
        hostname = match.group(1)  
        port = match.group(2) if match.group(2) else ""  
        return f"{hostname}:{port}" if port else hostname  
    else:  
        return None    

def merge_cidr_ranges(cidr_ranges):
    """
    Merges a list of CIDR ranges into the smallest possible list of CIDR ranges.

    Args:
        cidr_ranges (list): A list of CIDR ranges to be merged.

    Returns:
        list: The smallest possible list of CIDR ranges that includes all the original CIDR ranges.

    Examples:
        >>> merge_cidr_ranges(['192.168.0.0/24', '192.168.1.0/24', '192.168.2.0/24'])
        [IPNetwork('192.168.0.0/22')]
        >>> merge_cidr_ranges(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])
        [IPNetwork('10.0.0.0/8'), IPNetwork('172.16.0.0/12'), IPNetwork('192.168.0.0/16')]
    """
    ip_networks = [IPNetwork(cidr) for cidr in cidr_ranges]
    return cidr_merge(ip_networks)

def exclude_ips(cidr_ranges, exclude_ips):  
    """
    Excludes a list of IP addresses from a list of CIDR ranges.

    Args:
        cidr_ranges (list): A list of CIDR ranges to exclude IP addresses from.
        exclude_ips (list): A list of IP addresses to exclude from the CIDR ranges.

    Returns:
        list: A list of CIDR ranges that excludes the given IP addresses.

    Examples:
        >>> exclude_ips(['192.168.0.0/24', '192.168.1.0/24', '192.168.2.0/24'], ['192.168.0.1', '192.168.1.1'])
        ['192.168.0.2/31', '192.168.0.4/30', '192.168.0.8/29', '192.168.0.16/28', '192.168.0.32/27', '192.168.0.64/26', '192.168.0.128/25', '192.168.2.0/24']
    """
    result_ranges = []  
    for cidr in cidr_ranges:  
        ip_net = ipaddress.ip_network(cidr, strict=False)  
        new_subnets = [ip_net]  

        for exclude_ip in exclude_ips:  
            ip = ipaddress.ip_address(exclude_ip)  
            temp_subnets = []  
            for subnet in new_subnets:  
                if ip in subnet:  
                    temp_subnets.extend(list(subnet.address_exclude(ipaddress.ip_network(f'{ip}/32'))))  
                else:  
                    temp_subnets.append(subnet)  
            new_subnets = temp_subnets  
        result_ranges.extend(new_subnets)  

    # merge
    result_ranges = ipaddress.collapse_addresses(result_ranges)

    # convert to strings
    result_ranges = [str(cidr) for cidr in result_ranges]

    # sort 
    result_ranges.sort(key=lambda x: ipaddress.ip_network(x).network_address)

    return result_ranges  

def process_input(input_file, exclude_file=None):
    """
    Processes a list of IP addresses and hostnames from a file and returns a list of CIDR ranges.

    Args:
        input_file (str): The path to the file containing the list of IP addresses and hostnames.
        exclude_file (str, optional): The path to the file containing the list of IP addresses to exclude. Defaults to None.

    Returns:
        list: A list of CIDR ranges.

    Examples:
        >>> process_input('/home/user/ips.txt')
        ['192.168.0.0/24', '192.168.1.0/24', '192.168.2.0/24']
    """
    with open(input_file, 'r') as f:
        lines = f.readlines()

    cidr_ranges = []

    for line in lines:
        line = line.strip()

        if is_ip(line) or is_cidr(line):
            ip_network = ipaddress.ip_network(line, strict=False)
            cidr_ranges.append(str(ip_network))
        else:
            hostname = extract_hostname(line)
            if hostname:
                ip = hostname_to_ip(hostname)
                if ip:
                    ip_network = ipaddress.ip_network(ip, strict=False)
                    cidr_ranges.append(str(ip_network))

    if exclude_file:
        with open(exclude_file, 'r') as f:
            exclude_lines = f.readlines()

        exclude_ips_list = []

        for line in exclude_lines:
            line = line.strip()

            if is_ip(line) or is_cidr(line):
                ip_network = ipaddress.ip_network(line, strict=False)
                exclude_ips_list.extend(list(ip_network.hosts()))
            else:
                hostname = extract_hostname(line)
                if hostname:
                    ip = hostname_to_ip(hostname)
                    if ip:
                        exclude_ips_list.append(ip)

        cidr_ranges = exclude_ips(cidr_ranges, exclude_ips_list)

    return [str(cidr) for cidr in cidr_ranges]

def process_port_exclusions(port_exclusions_file=None):
    """
    This function processes a file containing IP addresses, CIDR ranges, and/or hostnames with port numbers to exclude.
    It returns a list of tuples containing the CIDR range and port number to exclude.

    Args:
    - port_exclusions_file (str): The path to the file containing the IP addresses, CIDR ranges, and/or hostnames with port numbers to exclude.

    Returns:
    - exclude_ips_list (list): A list of tuples containing the CIDR range and port number to exclude.

    Example:
    If the file '/home/user/exclude_ports.txt' contains the following:
    192.168.1.1:22
    10.0.0.0/24:80
    example.com:443

    Then calling process_port_exclusions('/home/user/exclude_ports.txt') will return:
    [('192.168.1.1/32', '22'), ('10.0.0.0/24', '80'), ('93.184.216.34/32', '443')]
    """
    if port_exclusions_file:  
        with open(port_exclusions_file, 'r') as f:  
            exclude_lines = f.readlines()  

            exclude_ips_list = []  

            for line in exclude_lines:  
                line = line.strip()  

                if is_ip_port(line):
                    ip_port = line.split(':')
                    if len(ip_port) != 2:
                        continue

                    cidr = ip_port[0] + "/32"
                    port = ip_port[1]

                    exclude_ips_list.append((cidr, port))
                elif is_cidr_port(line):  
                    # try to split line on :, make line first part and port second part
                    # if this fails, then it is not a valid cidr port
                    cidr_port = line.split(':')
                    if len(cidr_port) != 2:
                        continue
                    
                    cidr = cidr_port[0]
                    port = cidr_port[1]
            
                    # get cird range and port number
                    exclude_ips_list.append((cidr, port))
                else:  
                    hostname_port = extract_hostname_port(line)  
                    if hostname_port:  
                        # hostname is first split of :, port is second split
                        hostname_port = hostname_port.split(':')
                        if len(hostname_port) != 2:
                            continue

                        hostname = hostname_port[0]
                        port = hostname_port[1]

                        cidr = hostname_to_ip(hostname)  + "/32"
                        if cidr:  
                            exclude_ips_list.append((cidr,port))  

        # list of cidr
        return exclude_ips_list

def portselection():
    """
    Returns a list of commonly used ports for network scanning.

    Returns:
    ports (list): A list of integers representing commonly used ports for network scanning.

    Example:
    >>> portselection()
    [21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 137, 139, 143, 389, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5900, 8080, 8443, 8000, 8444, 8888, 9100, 9200, 11211, 32771]
    """
    
    ports = []
    ports.append(21) # ftp
    ports.append(22) # ssh
    ports.append(23) # telnet
    ports.append(25) # smtp
    ports.append(53) # dns
    ports.append(69) # tftp
    ports.append(80) # http
    ports.append(88) # kerberos
    ports.append(110) # pop3
    ports.append(111) # rpcbind
    ports.append(119) # nntp
    ports.append(123) # ntp
    ports.append(135) # msrpc
    ports.append(137) # smb
    ports.append(139) # netbios-ssn
    ports.append(143) # imap
    ports.append(161) # snmp
    ports.append(162) # snmptrap
    ports.append(179) # bgp
    ports.append(389) # ldap
    ports.append(443) # https
    ports.append(445) # microsoft-ds
    ports.append(465) # smtps
    ports.append(514) # syslog
    ports.append(543) # klogin
    ports.append(544) # kshell
    ports.append(587) # SMTP submission
    ports.append(993) # imaps
    ports.append(995) # pop3s
    ports.append(1194) # openvpn
    ports.append(1433) # mssql
    ports.append(1521) # oracle
    ports.append(1723) # pptp
    ports.append(2375) # docker
    ports.append(3306) # mysql
    ports.append(3389) # RDP
    ports.append(4712) #??
    ports.append(4786) #cisco
    ports.append(5555) #??
    ports.append(5900) # vnc
    ports.append(5900) # vnc
    ports.append(6379) # redis
    ports.append(7001) # afs3-callback
    ports.append(8080) # http-proxy/apache-tomcat
    ports.append(8443) # https-alt
    ports.append(8000) # http-alt
    ports.append(8444) # https-alt
    ports.append(8888) # sun-answerbook
    ports.append(9000) # clickhouse
    ports.append(9100) # jetdirect
    ports.append(9200) # elasticsearch
    ports.append(11211) # memcached
    ports.append(27017) # mongodb
    ports.append(32771) # sometimes used for rpcbind

    return ports

def get_host_data(ip):  
    """
    Scans single ip address based on internetdb
    """
    try:  
        response = requests.get(f"https://internetdb.shodan.io/{ip}")  
        if response.status_code == 200:  
            return response.json()  
        elif response.status_code == 404:
            return None
        elif response.status_code == 429:
            print("Rate limit exceeded. Waiting 5 seconds...")
            time.sleep(5)
        else:  
            print(f"Error {response.status_code} for IP: {ip}")  
            return None  
    except Exception as e:  
        print(f"Error: {e}")  
        return None  

def scan_subnet(subnet):  
    print(subnet)
    """
    Scans subnet based on internetdb
    Tries to scan 10 hosts at a time
    """
    ip_range = ipaddress.IPv4Network(subnet, strict=False)  
    results = []  

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:  
        future_to_ip = {executor.submit(get_host_data, str(ip)): ip for ip in ip_range}  
        for future in concurrent.futures.as_completed(future_to_ip):  
            ip = future_to_ip[future]  
            try:  
                result = future.result()  
                if result:  
                    results.append(result)  
            except Exception as exc:  
                print(f"{ip} generated an exception: {exc}")  

    return results  

    # subnet = "192.168.1.0/24"  
    # results = scan_subnet(subnet)  

    # for host in results:  
    #     print("IP:", host["ip"])  
    #     print("Ports:", host["ports"])  
    #     print("Hostnames:", host["hostnames"])  
    #     print("CPEs:", host["cpes"])  
    #     print("Tags:", host["tags"])  
    #     print("Vulnerabilities:", host["vulns"])  
    #     print("=" * 60)  

def connect_to_db():
    # Connect to the MySQL database  
    conn = mysql.connector.connect(  
    host="localhost",  
    user="orcestrator",  
    password="a8DL4Zsj77@lk",  
    database="orcestration"  
    )  
    
    # create a curson to the database
    cursor = conn.cursor()  

    return cursor, conn

def get_lasthop(cursor):
    # get current lasthop from global database
    get_lasthop_query = "SELECT lasthop FROM general_statistics ORDER BY id DESC LIMIT 1"  
    cursor.execute(get_lasthop_query)  
    result = cursor.fetchone()  
    lasthop_value = result[0]
    return lasthop_value

def add_alive_ip(cursor, conn, alive_ip, lasthop_value, cpe=None, vulns=None):
    """
    Adds alive ip to database (or updates existing one).
    Adds cpe and vulns if provided.
    """

    # Check if the IP already exists in the database  
    check_query = "SELECT COUNT(*) FROM alive_ips WHERE ip_address = INET_ATON(%s)"  
    check_values = (alive_ip,)  
    cursor.execute(check_query, check_values)  
    result = cursor.fetchone()  
    
    # If the combination does not exist, insert it into the database  
    alive_id_ip = ""  
    if result[0] == 0:  
        query = ""  
        values = ""  
        if cpe == None:  
            if vulns == None:  
                # Insert an alive IP address into the alive_ips table  
                query = "INSERT INTO alive_ips (ip_address, certainty, lasthop) VALUES (INET_ATON(%s), %s, %s)"  
                values = (alive_ip, 1, lasthop_value)  
            else:  
                # Insert an alive IP address into the alive_ips table  
                query = "INSERT INTO alive_ips (ip_address, certainty, lasthop, vuln_list) VALUES (INET_ATON(%s), %s, %s, %s)"  
                values = (alive_ip, 1, lasthop_value, vulns)  
        else:  
            if vulns == None:  
                # Insert an alive IP address into the alive_ips table  
                query = "INSERT INTO alive_ips (ip_address, certainty, lasthop, cpe_list) VALUES (INET_ATON(%s), %s, %s, %s)"  
                values = (alive_ip, 1, lasthop_value, cpe)  
            else:  
                # Insert an alive IP address into the alive_ips table  
                query = "INSERT INTO alive_ips (ip_address, certainty, lasthop, cpe_list, vuln_list) VALUES (INET_ATON(%s), %s, %s, %s, %s)"  
                values = (alive_ip, 1, lasthop_value, cpe, vulns)  
    
        # Add alive ip to database  
        cursor.execute(query, values)  
        conn.commit()  
        alive_ip_id = cursor.lastrowid  

    else:  
        get_id_query = "SELECT id FROM alive_ips WHERE ip_address = INET_ATON(%s)"  
        get_id_values = (alive_ip,)  
        cursor.execute(get_id_query, get_id_values)  
        alive_ip_id = cursor.fetchone()[0]  

        # update lasthop to lasthop_value
        update_lasthop_query = "UPDATE alive_ips SET lasthop = %s WHERE id = %s"
        update_lasthop_values = (lasthop_value, alive_ip_id)
        cursor.execute(update_lasthop_query, update_lasthop_values)
        conn.commit()

        # set certainty to 1 (found now start tests)
        update_certainty_query = "UPDATE alive_ips SET certainty = 1 WHERE id = %s"
        update_certainty_values = (alive_ip_id,)
        cursor.execute(update_certainty_query, update_certainty_values)
        conn.commit()

        if cpe != None:
            # update cpe to cpe
            update_cpe_query = "UPDATE alive_ips SET cpe_list = %s WHERE id = %s"
            update_cpe_values = (cpe, alive_ip_id)
            cursor.execute(update_cpe_query, update_cpe_values)
            conn.commit()

        if vulns != None:
            # update vulns to vulns
            update_vulns_query = "UPDATE alive_ips SET vuln_list = %s WHERE id = %s"
            update_vulns_values = (vulns, alive_ip_id)
            cursor.execute(update_vulns_query, update_vulns_values)
            conn.commit()

    return alive_ip_id

def add_alive_port(cursor, conn, alive_ip_id, alive_port, lasthop_value):
    # Check if the port already exists in the database  
    port_check_query = '''  
        SELECT COUNT(*), id  
        FROM open_ports_banners  
        WHERE alive_ip_id = %s AND open_port = %s  
    '''  
    port_check_values = (alive_ip_id, alive_port)  
    cursor.execute(port_check_query, port_check_values)  
    result = cursor.fetchone()  
    portexists = result[0] > 0 

    if not portexists:
        # Insert open ports and banners into the open_ports_banners table  
        open_ports_banners_data = [  
            (alive_ip_id, alive_port, "BANNERHERE??", 1, lasthop_value),   
        ]  

        insert_open_ports_banners_query = '''  
            INSERT INTO open_ports_banners (  
                alive_ip_id,  
                open_port,  
                banner,  
                certainty,  
                lasthop  
            ) VALUES (%s, %s, %s, %s, %s)  
        '''  
        
        for data in open_ports_banners_data:  
            cursor.execute(insert_open_ports_banners_query, data)  
        
        # Commit the changes and close the database connection  
        conn.commit() 
    else:
        # Get the ID of the existing port  
        port_id = result[1]  
        #print(f"Port already exists with ID: {port_id}")  

        # update lasthop to lasthop_value
        update_lasthop_query = "UPDATE open_ports_banners SET lasthop = %s WHERE id = %s"
        update_lasthop_values = (lasthop_value, port_id)
        cursor.execute(update_lasthop_query, update_lasthop_values)
        conn.commit()

        # set certainty to 1 (found now start tests)
        update_certainty_query = "UPDATE open_ports_banners SET certainty = 1 WHERE id = %s"
        update_certainty_values = (port_id,)
        cursor.execute(update_certainty_query, update_certainty_values)
        conn.commit()

def internetdb(cidrstring):
    """
    Scans CIDR ranges using internetdb.shodan.io
    """
    print_finding("scanner", f"shodan_findings.json", "info", "internetdb", "Querying all ip's in shodan databases")

    # connect to database
    cursor, conn = connect_to_db()

    # get current lasthop from global database
    lasthop_value = get_lasthop(cursor)

    # Iterate through the CIDR ranges and ports, creating a string so we can scan once per port (instead of once per cidr string per port)
    # cidrstring = "" 
    # for cidr_range in cidr_ranges:  
    #     print(cidr_range)
    #     if cidrstring == "":
    #         cidrstring = str(cidr_range)
    #     else:
    #         cidrstring = cidrstring + " " + str(cidr_range)

    # Iterate over cidr ranges
    for cidr in cidrstring:
        cidr = str(cidr)
        if cidr != "":
            result = scan_subnet(cidr)

            for host in result:  
                ip = host["ip"]
                ports = host["ports"]

                cpe = host["cpes"]
                vulns = host["vulns"]

                # convert above to to json
                cpe = json.dumps(cpe)
                vulns = json.dumps(vulns)

                alive_ip_id = add_alive_ip(cursor, conn, ip, lasthop_value, cpe, vulns)

                for port in ports:
                    add_alive_port(cursor, conn, alive_ip_id, port, lasthop_value)

    # close the connection
    conn.close()

async def masscan_task(cidrstring, port, exclude_port_file=None, output_file='output', banner_grab=False):
    if banner_grab:
        print_finding("scanner", f"{output_file}", "info", "masscan", f"Scanning on port {port}, getting banners")
        masscan_command = f'masscan {cidrstring} -p{port} --banners -oL {output_file} --excludefile {exclude_port_file} --max-rate 3333 --source-ip {SOURCE_IP}'
    else:
        print_finding("scanner", f"{output_file}", "info", "masscan", f"Scanning on port {port}")
        masscan_command = f'masscan {cidrstring} -p{port} -oL {output_file} --excludefile {exclude_port_file} --max-rate 3333'

    process = await asyncio.create_subprocess_shell(masscan_command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)  
    stdout, stderr = await process.communicate()  

    if process.returncode != 0:  
        print(f"Error: {stderr.decode()}")  

async def masscan(cidr_ranges, ports, exclude_port_file=None, output_directory='output'):  
    """
    Scans a list of CIDR ranges for open ports using masscan.
    It saves each port data in a a seperate file and takes exclusions on single port basis.
    It also generates banner files for ports which support this.

    Args:
    cidr_ranges (list): A list of CIDR ranges to scan.
    ports (list): A list of ports to scan.
    exclude_port_file (str, optional): A file containing IP:port, domain:port, or CIDR:port combinations to exclude from the scan. Defaults to None.
    output_directory (str, optional): The directory to output the scan results. Defaults to 'output'.

    Example:
    >>> cidr_ranges = ['192.168.0.0/24', '10.0.0.0/8']
    >>> ports = [80, 443, 8080]
    >>> masscan(cidr_ranges, ports, exclude_port_file='exclude_ports.txt', output_directory='scan_results')
    """

    # returns list op tuples of (cidr, port)
    portexclusions = process_port_exclusions(exclude_port_file)

    # Iterate through the CIDR ranges and ports, creating a string so we can scan once per port (instead of once per cidr string per port)
    cidrstring = "" 
    for cidr_range in cidr_ranges:  
        if cidrstring == "":
            cidrstring = str(cidr_range)
        else:
            cidrstring = cidrstring + " " + str(cidr_range)
    print_finding("progress", "final_cidr.txt", "info", "cidr_processed", "CIDR conversion and exclusion done")
    print("cidr: " + cidrstring)

    banner_grabbing_ports = [21, 80, 143, 11211, 110, 25, 22, 443, 139, 445, 23, 5900]

    # scanning per port
    tasks = []
    for port in ports:  
        output_file = os.path.join(output_directory, f'port_{port}.txt')  

        banner_grabbing = False
        if port in banner_grabbing_ports:
            banner_grabbing = True
        
        portexclusions = []
        # first match with port exclusions
        for cidr, exclude_port in portexclusions:
            if port == exclude_port:
                portexclusions.append(cidr)

        # write exclusions to file for masscan usage
        with open(f'exclude_port_{port}.txt', 'w') as f:
            for cidr in portexclusions:
                f.write(cidr + '\n')

        # sleep 10 seconds
        await asyncio.sleep(10)
        task = asyncio.create_task(masscan_task(cidrstring, port, exclude_port_file=f'exclude_port_{port}.txt', output_file=output_file, banner_grab=banner_grabbing))
        tasks.append(task)
        
        #TODO: even faster by further asyncio? so far breaks things
        await asyncio.gather(*tasks)

        # starting parse to database
        parse_to_database(output_file)
        # done with parse to database

parsed_level = False

#TODO 2: lock mechanism and database usage for scanners

def parse_to_database(portfile):
    # parses output to database
    cursor, conn = connect_to_db()

    # talk to the database
    database_newresults(portfile, cursor, conn)

    # close the connection
    conn.close()

def database_newtask(portfile, cursor, conn):
    """
    We expect a full path from portfile
    """

    # get port from portfile (remove .txt, find first slash from right, make substring from there, then remove port_)
    port = portfile[:-4]
    port = port[port.rfind('/')+1:]
    port = port[5:]

    # get current lasthop from global database
    lasthop_value = get_lasthop(cursor)

    # create task -> task status is progress int (1-100),0 is not started, 101 is paused, 102 - error,
    task_name = f"Scanning task for port {port}"  
    task_status = 0  

    # insert the new task into the running_tasks table  
    insert_task_query = (  
        "INSERT INTO running_tasks (task_name, task_status, lasthop) "  
        "VALUES (%s, %s, %s)"  
    )  
    cursor.execute(insert_task_query, (task_name, task_status, lasthop_value))  
    conn.commit()  

def database_newresults(portfile, cursor, conn):
    """
    We expect a full path from portfile
    """

    # get current lasthop from global database
    get_lasthop_query = "SELECT lasthop FROM general_statistics ORDER BY id DESC LIMIT 1"  
    cursor.execute(get_lasthop_query)  
    result = cursor.fetchone()  
    
    lasthop_value = -1
    if result:  
        lasthop_value = result[0]  
        print(f"Current lasthop value: {lasthop_value}")  
    else:  
        lasthop_value = -1
        print("No lasthop value found in the general_statistics table")


    # If the lasthop value does not exist, insert it into the general_statistics table
    global parsed_level
    if parsed_level == False:
        # update lasthop we got earlier by incrementing by 1
        lasthop_value = lasthop_value + 1
        if lasthop_value == 0:
            insert_query = "INSERT INTO general_statistics (lasthop) VALUES (%s)"
            insert_values = (lasthop_value,)
            cursor.execute(insert_query, insert_values)
            conn.commit()
            parsed_level = True
        else:
            # If the lasthop value already exists, update it
            update_query = "UPDATE general_statistics SET lasthop = %s WHERE lasthop = %s"
            update_values = (lasthop_value, lasthop_value - 1)
            cursor.execute(update_query, update_values)
            conn.commit()
            parsed_level = True

    # TODO: when a single port is done, it can be added to the database (while masscan is still running) (instead of masscan now waiting, paralellize)
    with open(portfile) as infile:
        for line in infile:
            if "open" in line:

                # gather data to add to database
                parts = line.split()
                alive_ip = parts[3]
                alive_port = parts[2]

                #? ALIVE IP DATABASE
                #TODO: think about retention period? when do we clean up database before it becomes huge
                #TODO: implement three times 1 hour rescan of alive ips to decide certainty

                alive_ip_id = add_alive_ip(cursor, conn, alive_ip, lasthop_value)

                #? OPEN PORT DATABASE``
                #TODO: integrate banner into database (not really needed as not much of banner present)
                add_alive_port(cursor, conn, alive_ip_id, alive_port, lasthop_value)
                # # Check if the port already exists in the database  
                # port_check_query = '''  
                #     SELECT COUNT(*), id  
                #     FROM open_ports_banners  
                #     WHERE alive_ip_id = %s AND open_port = %s  
                # '''  
                # port_check_values = (alive_ip_id, alive_port)  
                # cursor.execute(port_check_query, port_check_values)  
                # result = cursor.fetchone()  
                # portexists = result[0] > 0 

                # if not portexists:
                #     # Insert open ports and banners into the open_ports_banners table  
                #     open_ports_banners_data = [  
                #         (alive_ip_id, alive_port, "BANNERHERE??", 1, lasthop_value),   
                #     ]  

                #     insert_open_ports_banners_query = '''  
                #         INSERT INTO open_ports_banners (  
                #             alive_ip_id,  
                #             open_port,  
                #             banner,  
                #             certainty,  
                #             lasthop  
                #         ) VALUES (%s, %s, %s, %s, %s)  
                #     '''  
                    
                #     for data in open_ports_banners_data:  
                #         cursor.execute(insert_open_ports_banners_query, data)  
                    
                #     # Commit the changes and close the database connection  
                #     conn.commit() 
                # else:
                    # # Get the ID of the existing port  
                    # port_id = result[1]  
                    # #print(f"Port already exists with ID: {port_id}")  

                    # # update lasthop to lasthop_value
                    # update_lasthop_query = "UPDATE open_ports_banners SET lasthop = %s WHERE id = %s"
                    # update_lasthop_values = (lasthop_value, port_id)
                    # cursor.execute(update_lasthop_query, update_lasthop_values)
                    # conn.commit()

                    # # set certainty to 1 (found now start tests)
                    # update_certainty_query = "UPDATE open_ports_banners SET certainty = 1 WHERE id = %s"
                    # update_certainty_values = (port_id,)
                    # cursor.execute(update_certainty_query, update_certainty_values)
                    # conn.commit()

        # we create a scanning task per port
        database_newtask(portfile, cursor, conn)

def cleanup(output_directory):
    """
    This function removes all files in the current folder that start with "exclude_port_" and all empty txt files in the output folder.

    Args:
    - output_directory (str): The directory where the output files are stored.

    Returns:
    - None

    Example:
    cleanup("output")
    """
    # remove all files in current folder that start with exclude_port_
    for filename in os.listdir("."):
        if filename.startswith("exclude_port_"):
            os.remove(filename)

    # remove all empty txt files in output folder
    for filename in os.listdir(output_directory):
        if filename.endswith(".txt"):
            if os.stat(os.path.join(output_directory, filename)).st_size == 0:
                os.remove(os.path.join(output_directory, filename))

def read_file_content(file_name):  
    with open(file_name, "r") as file:  
        content = file.read()  
    return content  

def write_file_content(file_name, content):  
    with open(file_name, "w") as file:  
        file.write(content)  

def check_and_compare_files(input_file, cache_file):  
    if not os.path.exists(cache_file):  
        content = read_file_content(input_file)  
        write_file_content(cache_file, content)  
        print_finding("debug", "inputcache.txt", "info", "caching", "No cache found, cache file created")
        return False
    else:  
        input_content = read_file_content(input_file)  
        cache_content = read_file_content(cache_file)  
        
        if input_content == cache_content:      
            print_finding("debug", "inputcache.txt", "info", "caching", "Cache can be used")
            return True
        else:  
            write_file_content(cache_file, input_content)  
            print_finding("debug", "inputcache.txt", "info", "caching", "New input found, updating cache...")
            return False

def combine_files(output_folder):
    """
    Combine all files in output_folder that contain ip:port content into one file.
    """
    with open(output_folder + "/combined.txt", "w") as outfile:
        path = output_folder + "/combined.txt"
        print_finding("scanner", f"{path}", "info", "combinator", f"Combining all output in single file")
        for filename in os.listdir(output_folder):
            if filename.endswith(".txt") and "banner" not in filename:
                with open(output_folder + "/" + filename) as infile:
                    for line in infile:
                        if "open" in line:
                            parts = line.split()
                            outfile.write(parts[3] + ":" + parts[2] + "\n")

if __name__ == '__main__':  
    if len(sys.argv) < 2:  
        print("Usage: python preprocess.py <input_file.txt> [exclude_file.txt] [exclude_port_file.txt]")  
        sys.exit(1)  

    input_file = sys.argv[1]  

    if (str(input_file)) == "help":
        helpmenu()       
    if (str(input_file).endswith(".txt") == False):
        print("Usage: python preprocess.py <input_file.txt> [exclude_file.txt] [exclude_port_file.txt]")  
        sys.exit(1)

    asciiart()
    exclude_file = sys.argv[2] if len(sys.argv) > 2 else "full_scope_exclude.txt"  
    exclude_port_file = sys.argv[3] if len(sys.argv) > 3 else None

    # get current date+time in single string
    now = datetime.now()
    dt_string = now.strftime("%d-%m-%Y_%H-%M-%S")
    outputfolder = "output/output_" + dt_string

    if not os.path.exists(outputfolder):  
        os.makedirs(outputfolder)  

    cleanup(outputfolder)

    # cidr_ranges = process_input(input_file, exclude_file)  

    # read content of input_file into one single string, check if inputcache.txt exists, if exists compare data with input_file, create if else for same or not some content
    alreadycached = check_and_compare_files(input_file, "inputcache.txt")  

    # Format exclude file = domain,ip or CIDR
    # Format exclude port file = ip:port combo, domain:port combo, CIDR:port combo
    outputstring = "final_cidr.txt"
        
    if not alreadycached and True==False:
        # now write output to file final_cird.txt in output folder
        merged_cidr_ranges = merge_cidr_ranges(cidr_ranges)  
        with open(outputstring, 'w') as f:
            for cidr_range in merged_cidr_ranges:
                f.write(str(cidr_range) + '\n')
    else:
        merged_cidr_ranges = []
        with open(outputstring, 'r') as f:
            for line in f:
                merged_cidr_ranges.append(line.strip())

    ports_toscan = portselection()

    # create output with masscan
    asyncio.run(masscan(merged_cidr_ranges, ports_toscan, exclude_port_file, outputfolder))

    # create output with internetdb
    #internetdb(merged_cidr_ranges)

    # now from all files in output folder, create one file which combines ip:port content from all other files
    combine_files(outputfolder)
    cleanup(outputfolder)

    # nuclei optimization
    # nuclei -l combined.txt -s critical -rl 1500 -bs 300 -c 10