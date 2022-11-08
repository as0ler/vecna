#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author : Murphy, atorralba
# LICENSE: GPL v3


import argparse
import time
import os
import r2pipe
import sys
from adbutils import adb
from console import print_console, ERROR, SUCCESS, WARN, DEBUG
from device import get_usb_device

OUTPUT_FILE = 'out/vulnapps.txt'
CACHE_FILE = '.vecna-cache'
global EXPORTED_PROVIDER


def is_a_valid_apk(r2):
    return bool(r2.cmd('oj~{=}~classes.dex').replace('"', '').strip())


def has_non_exported_provider(r2):
    return bool(r2.cmd('pFAj~{=}~provider~false').replace('"', '').strip())


def get_package_name(r2):
    package_name = r2.cmd(
        'pFAj~{=}~json.manifest.package[1]').replace('"', '').strip()
    return package_name


def list_apk_folder(path):
    result = [
        os.path.join(path, filename)
        for filename in os.listdir(path)
        if os.path.splitext(filename)[1] == '.apk'
    ]
    result.sort()
    return result


def save_vulnerable_app(package_name, class_name):
    try:
        with open(OUTPUT_FILE, 'a') as fd:
            fd.write(f'{package_name},{class_name},{EXPORTED_PROVIDER}\n')
    except:
        print_console(f'Unable to open or create {OUTPUT_FILE}', ERROR)
        sys.exit(-1)


def on_message(message, _):
    if not message:
        return
    try:
        if message.get('payload', {}).get('type') == 'log-event':
            print_console(message['payload']['msg'])
        if message.get('payload', {}).get('type') == 'vuln-event':
            print_console(message['payload']['msg'], SUCCESS)
            save_vulnerable_app(
                message['payload']['packageName'], message['payload']['className'])

    except Exception as e:
        print_console(
            f'Failed to process an incoming message from agent: {e}', ERROR)


def get_cache():
    if not os.path.exists(CACHE_FILE):
        return None
    with open(CACHE_FILE) as f:
        cache = f.read().strip()
    print_console(f'Cache file found. Fast-forwarding to {cache}.', DEBUG)
    return cache


def write_cache(apk_file):
    with open(CACHE_FILE, "w") as f:
        f.write(apk_file)


def main():
    global EXPORTED_PROVIDER
    parser = argparse.ArgumentParser(description='vecna by Murphy')
    parser.add_argument('-p', '--path', type=str,
                        help='Defines the path of the APKs to analyze')
    arguments = parser.parse_args()
    if not arguments.path:
        print_console('APK path is required', ERROR)
        sys.exit(-1)
    device = get_usb_device()
    adb_device = adb.device()
    applications = list_apk_folder(arguments.path)
    idx = 0
    cache = get_cache()
    for apk_file in applications:
        idx = idx + 1
        if cache and apk_file != cache:
            continue
        cache = None
        write_cache(apk_file)
        print_console(f'Analyzed {idx}/{len(applications)}', DEBUG)
        EXPORTED_PROVIDER = False
        pid = None
        script = None
        package_name = None
        try:
            print_console(f'Opening {apk_file} with radare2')
            r2 = r2pipe.open(f'apk://{apk_file}')
            if (not is_a_valid_apk(r2)):
                print_console(f'Invalid APK {apk_file}. Skipping...', WARN)
                continue
            r2.cmd('op `o~AndroidManifest:0[0]`')
            r2.cmd('s 0x00;b $s')
            print_console(f'Obtaining package name from {apk_file}')
            package_name = get_package_name(r2)
            if (not package_name):
                print_console(f'No package name found. Skipping...', WARN)
                continue
            print_console(f'Obtaining providers from {apk_file}')
            EXPORTED_PROVIDER = has_non_exported_provider(r2)
            print_console(f'Installing {apk_file}')
            adb_device.install(apk_file, nolaunch=True)
            print_console(f'Spawning {package_name}')
            pid = device.spawn([package_name])
            device.resume(pid)
            session = device.attach(pid)
            script_path = './mindflayer.js'
            with open(script_path, 'r') as hook:
                script = session.create_script(hook.read())
            if not script:
                print_console(
                    f'The specified script {script_path} was not found!', ERROR)
                sys.exit(-1)
            script.on('message', on_message)
            script.load()
            print_console(f'Running exploit')
            script.exports.exploit()
            time.sleep(1)
        except Exception as err:
            print_console(
                f'Error occurred analyzing {apk_file}. error: {err}', ERROR)
        finally:
            if script:
                try:
                    script.unload()
                except Exception as err:
                    pass
            if pid:
                print_console(f'Killing {package_name} with PID {pid}')
                try:
                    device.kill(pid)
                except Exception as err:
                    pass
            if package_name and package_name in adb_device.list_packages():
                print_console(f'Uninstalling {apk_file}')
                adb_device.uninstall(package_name)
            r2.quit()
    os.unlink(CACHE_FILE)


if __name__ == '__main__':
    main()
