#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy, atorralba
# LICENSE: GPL v3

from colorama import Fore, Style
import logging

# Global Vars
INFO = 0
SUCCESS = 1
ERROR = 2
WARN = 3
DEFAULT = 4
DEBUG = 5
logging.basicConfig(filename='vecna.log', level=logging.DEBUG)


def print_console(msg, level=INFO, formatter=0):
    tabs, color = ["", ""]
    for _ in range(formatter):
        tabs += "    "
    if level == ERROR:
        msg = "[ERROR]  - " + msg
        color = Fore.RED
    elif level == SUCCESS:
        msg = "[VULNERABLE]  - " + msg
        color = Fore.LIGHTCYAN_EX
    elif level == WARN:
        msg = "[WARN] - " + msg
        color = Fore.YELLOW
    elif level == DEBUG:
        msg = "[DEBUG] " + msg
        color = Fore.BLUE
    elif level == INFO:
        msg = "[+] " + msg
    print(color + tabs + msg + Style.RESET_ALL)
    logging.info(msg)
