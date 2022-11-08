#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy, atorralba
# LICENSE: GPL v3

import sys
import threading
import frida
from console import print_console, DEFAULT

def get_usb_device():
    device_type = 'usb'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)
    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == device_type]
        if len(devices) == 0:
            print_console('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]
    device_manager.off('changed', on_changed)
    return device
