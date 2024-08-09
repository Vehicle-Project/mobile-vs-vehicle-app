from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodAnalysis

from loguru import logger
import pandas as pd
import paramiko
import numpy as np
import os
import urllib.request
import urllib.error
import socket
from threading import Thread, Lock
import math
import hashlib
import requests
from lxml import etree
import os
import time
import json
import pycurl
import certifi
from io import BytesIO
from sys import stderr as STREAM
import multiprocessing as mp
import time
import struct



logger.remove()

parent_path = "/home/project/Documents/Car/Apps/Third_APP/"

result2_path = "/home/project/Documents/Car/Behavior_Detection/Third_APP_Result/"

import logging
# logging.basicConfig(filename=parent_path+"analysis.log",
#     level=logging.DEBUG,
#     format='%(asctime)s - %(levelname)s - %(message)s')
# Create a logger（Logger）
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create file handler（FileHandler）to write logs to a file
file_handler = logging.FileHandler(parent_path + 'log_file4.log')
file_handler.setLevel(logging.DEBUG)

# Create a console processor (StreamHandler) to output logs to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Create a log formatter（Formatter）
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Add the log renderer to the processor
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the processor to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

import os
import json
import gc

import threading
import psutil
import multiprocessing
import time

AndroZooKey = "27787e752bcb4d015a9c2fe6fdaf0ef54a628ff16af1f19ef15ffc7fd0664fbc"
thread_num = 16
cachesize = 1024 * 200
downloaded = 0
THREAD_POOL = []
mutex = Lock()
last_byte = 0
mutex_part = Lock()
single_size = 1024 * 1024

reset_time = 0

INTERVAL=5
THRESHOLD=88

BEHAVIORS = [
    ["Read Memory Card", ["READ_EXTERNAL_STORAGE"], [
        ["Landroid/os/Environment;", "getExternalStorageDirectory"],
        ["Landroid/os/Environment;", "getExternalStoragePublicDirectory"],
        ["Landroid/content/Context;", "getExternalFilesDir"],
    ]],
    ["Read Device Phone And Identification Status Information", ["READ_PHONE_STATE"], [
        ["Landroid/telephony/TelephonyManager", "getDeviceSoftwareVersion"],
        ["Landroid/telephony/TelephonyManager", "getNetworkType"],
        ["Landroid/telephony/TelephonyManager", "getSimSerialNumber"],
        ["Landroid/telephony/TelephonyManager", "getLine1Number"],
        ["Landroid/telephony/TelephonyManager", "getMeid"],
        ["Landroid/telephony/TelephonyManager", "getImei"],
        ["Landroid/telephony/TelephonyManager", "getDeviceId"],
        ["Landroid/telephony/TelephonyManager", "getSubscriberId"],
        ["Landroid/telephony/TelephonyManager", "getNetworkOperatorName"],
        ["Landroid/telephony/TelephonyManager", "getSimOperatorName"],
    ]],
    ["Floating Window", ["SYSTEM_ALERT_WINDOW"], [["Landroid/view/WindowManagerImpl", "addView"],
                                      ["Landroid/provider/Settings", "canDrawOverlays"]]],
    ["Camera", ["CAMERA"], [
        ["Landroid/hardware/Camera;", "takePicture"],
        ["Landroid/hardware/Camera;", "open"],
        ["Landroid/media/MediaRecorder;", "start"],
        ["Landroid/hardware/camera2/CameraManager;", "openCamera"],
        ["Landroid/hardware/Camera;", "startPreview"]
    ]],
    ["Get Location Information", ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"], [
        ["Landroid/location/LocationManager;", "getLastKnownLocation"],
        ["Landroid/location/LocationManager;", "requestLocationUpdates"],
        ["Landroid/location/LocationListener;", "onLocationChanged"],
        ["Landroid/location/Location;", "getLatitude"],
        ["Landroid/location/Location;", "getLongitude"],
        ["Landroid/location/Location;", "getAltitude"],
    ]],
    ["Get Bluetooth Matching Information", ["BLUETOOTH"], [
        ["Landroid/bluetooth/BluetoothAdapter;", "getBondedDevices"],
        ["Landroid/bluetooth/BluetoothDevice;", "getName"],
        ["Landroid/bluetooth/BluetoothDevice;", "getAddress"],
        ["Landroid/bluetooth/BluetoothDevice;", "getBondState"],
    ]],
    ["Read Wi-Fi Connection Records", ["ACCESS_WIFI_STATE"], [
        ["Landroid/net/wifi/WifiManager;", "getConfiguredNetworks"],
        ["Landroid/net/wifi/WifiManager;", "getConnectionInfo"],
        ["Landroid/net/wifi/WifiInfo;", "getSSID"],
        ["Landroid/net/wifi/WifiInfo;", "getBSSID"],
        ["Landroid/net/wifi/WifiInfo;", "getIpAddress"],
    ]],
    ["Read Recording Records", ["RECORD_AUDIO"], [
        ["Landroid/media/MediaRecorder;", "setAudioSource"],
        ["Landroid/media/MediaRecorder;", "setOutputFormat"],
        ["Landroid/media/MediaRecorder;", "setAudioEncoder"],
        ["Landroid/media/MediaRecorder;", "setOutputFile"],
        ["Landroid/media/MediaRecorder;", "prepare"],
        ["Landroid/media/MediaRecorder;", "start"],
        ["Landroid/media/MediaRecorder;", "stop"],
    ]],
    ["Notification Pop Up", ["POST_NOTIFICATIONS"], [
        ["Landroid/app/NotificationManager;", "notify"],
        ["Landroid/app/Notification/Builder;", "setSmallIcon"],
        ["Landroid/app/Notification/Builder;", "setContentTitle"],
        ["Landroid/app/Notification/Builder;", "setContentText"],
        ["Landroid/app/Notification/Builder;", "setPriority"],
        ["Landroid/app/Notification/Builder;", "setAutoCancel"],
    ]],
    ["Advertisement Pop Up", ["INTERNET", "ACCESS_NETWORK_STATE"], [
        ["Lcom/adnetwork/sdk/AdRequest;", "loadAd"],
        ["Lcom/adnetwork/sdk/AdRequest;", "setAdListener"],
        ["Lcom/adnetwork/sdk/InterstitialAd;", "show"],
        ["Lcom/adnetwork/sdk/AdView;", "setAdSize"],
        ["Lcom/adnetwork/sdk/AdView;", "setAdUnitId"],
        ["Lcom/adnetwork/sdk/AdListener;", "onAdLoaded"],
        ["Lcom/adnetwork/sdk/AdListener;", "onAdFailedToLoad"],
    ]],
    ["Voice Calls", ["CALL_PHONE"], [
        ["Landroid/telephony/TelephonyManager;", "listen"],
        ["Landroid/telephony/PhoneStateListener;", "onCallStateChanged"],
    ]],
    ["Music Playback", ["MEDIA_CONTENT_CONTROL", "WAKE_LOCK"], [
        ["Landroid/media/MediaPlayer;", "create"],
        ["Landroid/media/MediaPlayer;", "setDataSource"],
        ["Landroid/media/MediaPlayer;", "prepare"],
        ["Landroid/media/MediaPlayer;", "start"],
        ["Landroid/media/MediaPlayer;", "pause"],
        ["Landroid/media/MediaPlayer;", "stop"],
        ["Landroid/media/MediaPlayer;", "release"],
        ["Landroid/media/AudioManager;", "setStreamVolume"],
        ["Landroid/media/AudioAttributes$Builder;", "setContentType"],
        ["Landroid/media/AudioAttributes$Builder;", "setUsage"],
    ]],
    ["Video Playback", ["INTERNET", "ACCESS_WIFI_STATE"], [
        ["Landroid/media/MediaPlayer;", "setDataSource"],
        ["Landroid/media/MediaPlayer;", "prepare"],
        ["Landroid/media/MediaPlayer;", "start"],
        ["Landroid/media/MediaPlayer;", "stop"],
        ["Landroid/media/MediaPlayer;", "release"],
        ["Landroid/media/MediaPlayer;", "setVideoScalingMode"],
        ["Landroid/view/SurfaceView;", "setZOrderOnTop"],
        ["Landroid/view/SurfaceHolder;", "addCallback"],
        ["Landroid/media/MediaPlayer$OnPreparedListener;", "onPrepared"],
        ["Landroid/media/MediaPlayer$OnCompletionListener;", "onCompletion"],
        ["Landroid/media/MediaPlayer$OnErrorListener;", "onError"],
    ]],
    ["Video Calls", ["CAMERA", "RECORD_AUDIO", "INTERNET", "ACCESS_NETWORK_STATE", "MODIFY_AUDIO_SETTINGS"], [
        ["Landroid/hardware/Camera;", "open"],
        ["Landroid/hardware/Camera;", "startPreview"],
        ["Landroid/media/MediaRecorder;", "setAudioSource"],
        ["Landroid/media/MediaRecorder;", "setVideoSource"],
        ["Landroid/media/MediaRecorder;", "setOutputFormat"],
        ["Landroid/media/MediaRecorder;", "prepare"],
        ["Landroid/media/MediaRecorder;", "start"],
        ["Landroid/media/MediaRecorder;", "stop"],
        ["Landroid/net/sip/SipManager;", "makeAudioCall"],
        ["Landroid/net/sip/SipManager;", "makeVideoCall"],
        ["Landroid/net/sip/SipManager;", "setSpeakerMode"],
        ["Landroid/net/sip/SipAudioCall;", "start"],
        ["Landroid/net/sip/SipAudioCall;", "endCall"],
    ]],

]

def check_memory_usage(proc:multiprocessing.Process):
    while True:
        # Retrieve virtual memory information of the system
        virtual_memory = psutil.virtual_memory()
        used_memory_percent = virtual_memory.percent
        # logger.info(f"[*] check_memory_usage: used:{used_memory_percent}")
        # Check if the memory usage exceeds the threshold
        if used_memory_percent > THRESHOLD:
            # Memory usage is too high, triggering other logic
            # memory_exceeded.set()
            # logging.warning(f"[!] check_memory_usage: memory leak. terminating.")
            proc.terminate()
            # logging.warning(f"[!] check_memory_usage: terminated.")
            return
        if proc.is_alive() == False:
            # logger.info(f"[*] check_memory_usage: proc is terminated. terminating.")
            break
        # print("Memory usage is too high, triggering other logic")
        time.sleep(INTERVAL)
        # Wait for a while and check again
        # memory_exceeded.wait(INTERVAL)
    logger.info(f"[*] check_memory_usage: end.")
    return

def AnalyzeAPKMultiProc(path, file):
    logger.info(f"[*] AnalyzeAPKMultiProc: file:{path}")
    try:
        _apk, _dex, _dx = AnalyzeAPK(path)
        # pkg_name = _apk.get_package()
        # print(pkg_name)
    except:
        logger.error(f"[!] AnalyzeAPKMultiProc: failed in AnalyzeAPK with path:{path}")
        return
    
    try:
        logger.info(f"[*] AnalyzeAPKMultiProc: check_apk: {path},\n\tresult at {result2_path+file}._result2.json")
        check_apk(_apk, _dex, _dx, path, result2_path + pkg_name +"._result2.json")
    except:
        logger.error(f"[!] AnalyzeAPKMultiProc: error in check_apk")



    del _dex
    del _dx
    del _apk
    gc.collect()

    logger.info(f"[*] AnalyzeAPKMultiProc: finished")
    return


def analyze(path, recheck_all=True, apks=None, no_skip=False):
    if apks == None:
        files = os.listdir(path)
    else:
        files = apks
    for file in files:
        _path, file = os.path.split(file)
        if _path != "":
            _path += "/"
            path = _path

        if os.path.isdir(path+file):
            continue
        if ".json" in file:
            continue

        # APKID shell inspection
        if os.path.exists(path+file+".json") == False or \
            recheck_all:
            try:
                logger.info(f"[!] analyze: apkid file:{file}")
                os.system(f"apkid {path+file} -j > {path+file}.json")
            except:
                # print(f"apkid error. skiping {file}")
                logger.error(f"[!] analyze: apkid error. skiping {file}")
                continue
        
        try:
            with open(f"{path+file}.json", "r") as jres:
                jobj = json.load(jres)

                skip = False
                for _file in jobj['files']:
                    _matches = _file.get("matches")
                    if _matches is None:
                        continue
                    else:
                        _packer = _matches.get("packer")
                        if _packer:
                            # print(f"find packer {_packer} in file:{file}. skipping.")
                            logger.error(f"[!] analyze: find packer {_packer} in file:{file}. skipping.")
                            skip = True
                            break

                if skip:
                    continue
        except:
            logger.error(f"[!] analyze: apkid result load error. file: {file}")
            if no_skip == False:
                continue

        logger.info(f"[*] analyze: start analyzing {file}")

        proc = multiprocessing.Process(target=AnalyzeAPKMultiProc,
                                        args=(path+file, file))
        memory_check = threading.Thread(target=check_memory_usage, args=(proc,))
        proc.start()
        memory_check.start()

        logger.info(f"[*] analyze: join proc")
        proc.join()
        logger.info(f"[*] analyze: join memory_check")
        memory_check.join(timeout=6)
 

def is_packed(path):
    try:
        os.system(f"apkid {path} -j > {path}.apkid.json")
        with open(f"{path}.apkid.json", "r") as jres:
            jobj = json.load(jres)

            for _file in jobj['files']:
                _matches = _file.get("matches")
                if _matches is None:
                    continue
                else:
                    _packer = _matches.get("packer")
                    if _packer and type(_packer) == list and len(_packer) >= 1:
                        # print(f"find packer {_packer} in file:{file}. skipping.")
                        logger.error(f"[!] analyze: find packer {_packer} in {path}")
                        return True
        return False
    except:
        return True


result_path = "/home/project/Documents/Car/Result/Mobile_APP_Result/"


def AnalyzeAPKMultiProc_app(path, file):
    """Specially modified for use in mobile apps"""
    
    logger.info(f"[*] AnalyzeAPKMultiProc: file:{path}")
    try:
        _apk, _dex, _dx = AnalyzeAPK(path)
        # pkg_name = _apk.get_package()
        # print(pkg_name)
    except:
        logger.error(f"[!] AnalyzeAPKMultiProc: failed in AnalyzeAPK with path:{path}")
        return
    
    try:
        logger.info(f"[*] AnalyzeAPKMultiProc: check_apk: {path},\n\tresult at {result_path+file}._result2.json")
        check_apk(_apk, _dex, _dx, path, result_path+file+"._result2.json")
    except:
        logger.error(f"[!] AnalyzeAPKMultiProc: error in check_apk")



    del _dex
    del _dx
    del _apk
    gc.collect()

    logger.info(f"[*] AnalyzeAPKMultiProc: finished")
    return

    
def analyze_single(full_path, file):
    if is_packed(full_path):
        return
    
    logger.info(f"[*] start analyzing {full_path}")

    proc = multiprocessing.Process(target=AnalyzeAPKMultiProc_app,
                                    args=(full_path, file))
    memory_check = threading.Thread(target=check_memory_usage, args=(proc,))
    proc.start()
    memory_check.start()

    # logger.info(f"[*] analyze: join proc")
    proc.join()
    # logger.info(f"[*] analyze: join memory_check")
    memory_check.join(timeout=6)

    # try:
    #     result = json.load(open(result_path+file+"._result2.json"))

    #     result_bool = {}
    #     keys = list(result.keys())
    #     for key in keys:
    #         cate = result[key]
    #         permissions = cate['permissions']
    #         apis = cate['apis']
    #         # if cate['apis']
    #         if len(apis) == 0:
    #             result_bool[key] = 1
    #         else:
    #             result_bool[key] = 0

        
    #     return result
    # except:
    #     return None

def analyze_multi(pathdir:list):
    for path in pathdir:
        logger.info(f"[*] analyze: analyzing dir:{path}")
        analyze(path)

def find_apks(dir_path):
  """
  Thoroughly traverse a folder to retrieve all files with the. apk extension.
  Args:
  Dir_cath: Folder path.
  Returns:
  List of all files with the suffix. apk.
  """
  apk_files = []
  for root, dirs, files in os.walk(dir_path):
    for file in files:
      if file.endswith(".apk"):
        apk_files.append(os.path.join(root, file))
  return apk_files

def check_behavior(a, d, dx, behavior, permissions, apis, verbose=False):
    all_permissions = a.get_permissions()
    permission_results = []
    for tmp_p in permissions:
        for apk_p in all_permissions:
            if apk_p.endswith(tmp_p):
                permission_results.append(apk_p)
                break
    if verbose:
        all_permissions_str = ", ".join(permissions)
        print(f"Check if there is {all_permissions_str} permission in the Manifest;")
    api_results = []
    all_apis_str = []
    for api in apis:
        class_name = api[0]
        method_name = api[1]
        all_apis_str.append(class_name + "." + method_name)
        for method in dx.find_methods(classname=class_name, methodname=method_name):
            for _, call, _ in method.get_xref_from():
                api_results.append((call.class_name, call.name, class_name, method_name))
  
    if verbose:
        all_apis_str = ", ".join(all_apis_str)
        print(f"Check if the {all_apis_str} method is called in the Dex file;")


    return permission_results, api_results


def check_apk(a, d, dx, apk_path, output_path, idx=0):
    # a, d, dx = AnalyzeAPK(apk_path)
    results = {}
    for i in range(len(BEHAVIORS)):
        behavior = BEHAVIORS[i]
        results[behavior[0]] = {}
        permissions, apis = check_behavior(a, d, dx, behavior[0], behavior[1], behavior[2], True)
        results[behavior[0]]["permissions"] = permissions
        results[behavior[0]]["apis"] = apis

    with open(output_path, "w") as f:
        f.write(json.dumps(results, ensure_ascii=False))

def analyze_multi_sys(pathdir:list):
    for path in pathdir:
        logger.info(f"[*] analyze_multi_sys: analyzing dir:{path}")
        apks = find_apks(path)
        analyze(path, recheck_all=True, apks=apks, no_skip=True)



# =====================================================

# callback function for c.XFERINFOFUNCTION
def status(download_t, download_d, upload_t, upload_d):
    kb = 1024
    STREAM.write('Downloading: {}/{} kiB ({}%)\r'.format(
        str(int(download_d/kb)),
        str(int(download_t/kb)),
        str(int(download_d/download_t*100) if download_t > 0 else 0)
    ))
    STREAM.flush()

def download_single_pycurl(sha256, apikey, save_path):
    try:
        buffer = BytesIO()
        c = pycurl.Curl()
        # 0000003B455A6C7AF837EF90F2EAFFD856E3B5CF49F5E27191430328DE2FA670
        c.setopt(c.URL, f'https://androzoo.uni.lu/api/download?apikey={apikey}&sha256={sha256}')
        # c.setopt(c.URL, "www.google.com")
        c.setopt(c.WRITEDATA, buffer)
        c.setopt(c.CAINFO, certifi.where())
        # c.setopt(c.VERBOSE, True)
        c.setopt(c.SSL_VERIFYPEER, 0)
        c.setopt(c.SSL_VERIFYHOST, 0)
        c.setopt(c.TIMEOUT, 300)
        c.setopt(c.NOPROGRESS, False)
        c.setopt(c.XFERINFOFUNCTION, status)
        # c.setopt(c.SSLVERSION, 3)
        c.setopt(c.PROXY, "http://127.0.0.1")
        c.setopt(c.PROXYPORT, 20171)
        c.perform()
        c.close()

        body = buffer.getvalue()
        # print(body)
        with open(save_path, 'wb') as f:
            f.write(body)
        return True
    except:
        print(f"error downloading: {sha256}")
        return False


# def download_mt(startpos, endpos, _id, filesize, url, savepath):
#     global last_byte, reset_time
#     # if _id == thread_num-1:
#     #     endpos = filesize
#     completed = False
#     this_downloaded = 0
#     mutex_part.acquire()
#     if last_byte < filesize:
#         startpos = last_byte
#         if last_byte + single_size < filesize:
#             endpos = startpos + single_size
#             last_byte += single_size
#         else:
#             endpos = filesize
#             last_byte = filesize
#         mutex_part.release()
#     else:
#         mutex_part.release()
#         return
#     download_size = endpos-startpos
#     download_times = download_size // cachesize
#     last_download_size = download_size % cachesize
#     proxy_handler = urllib.request.ProxyHandler({
#         # 'http': '172.25.76.48:7892',
#         'http': '127.0.0.1:20171',
#         'https': '127.0.0.1:20171'
#     })
#     proxy_opener = urllib.request.build_opener(proxy_handler)
#     #urllib.request.install_opener(proxy_opener)
#     while (not completed) and (reset_time < thread_num):
#         try:
#             this_downloaded = 0
#             reqfile = urllib.request.Request(
#                 url, headers={'range': "bytes=%s-%s" % (startpos, endpos)})
#             reqfile = urllib.request.urlopen(reqfile, timeout=5)
#             #print("[Thread-%s] Downloading bytes:%s-%s." % (_id, startpos, endpos))
#             filename = "%s-%s" % (savepath, str(int(startpos//(single_size))))
#             with open(filename, 'wb') as sf:
#                 #print('cache {}-{} to {}'.format(startpos, endpos, filename))
#                 n = 0
#                 global downloaded
#                 while download_times > n:
#                     sf.write(reqfile.read(cachesize))
#                     n += 1
#                     mutex.acquire()
#                     downloaded += cachesize
#                     this_downloaded += cachesize
#                     print('\x1B[2KDownload Progress: {}%\t{}/{}'.format(int(downloaded*100.0/filesize), size2str(downloaded), size2str(filesize)), end='\r')
#                     mutex.release()
#                 if last_download_size != 0:
#                     sf.write(reqfile.read(last_download_size))
#                     mutex.acquire()
#                     downloaded += last_download_size
#                     this_downloaded += last_download_size
#                     print('\x1B[2KDownload Progress: {}%\t{}/{}'.format(int(downloaded*100.0/filesize), size2str(downloaded), size2str(filesize)), end='\r')
#                     mutex.release()
#             completed = True
#         except Exception as e:
#             if str(e) == '[Errno 104] Connection reset by peer':
#                 reset_time += 1
#             print("[Thread-%s] Download Failed: %s. Restarting..." % (_id, e))
#             mutex.acquire()
#             downloaded -= this_downloaded
#             mutex.release()
#         else:
#             mutex_part.acquire()
#             if last_byte < filesize:
#                 completed = False
#                 startpos = last_byte
#                 if last_byte + single_size < filesize:
#                     endpos = startpos + single_size
#                     last_byte += single_size
#                 else:
#                     endpos = filesize
#                     last_byte = filesize
#             mutex_part.release()
#             #print("[Thread-%s] Download Completed." % (_id))


# def check_folder(folder_name):
#     if not os.path.exists(folder_name):
#         os.mkdir(folder_name)

# def check_sha256(filepath,sha256_should_be):
#     flag = False
#     with open('/home/project/Documents/Car/broken_download.txt', 'a+') as b:
#         with open(filepath, 'rb') as f:
#             sha256_hash = hashlib.sha256()
#             while True:
#                 data = f.read(65536)
#                 if not data:
#                     break
#                 sha256_hash.update(data)
#             sha256 = sha256_hash.hexdigest()

#         # If the sha256 value in the file name is different from the actual calculated sha256 value, delete the file
#         if sha256_should_be != sha256.upper():
#             b.writelines(filepath+'\n')
#             flag = True
#     return (not flag)
    

def size2str(size):
    size = int(size)
    if size > 1<<40: #TB
        return (str(size*1.0/(1<<40)).split('.')[0]+'.'+str(size*1.0/(1<<40)).split('.')[1][:2]+' TiB')
    elif size > 1<<30: #GB
        return (str(size*1.0/(1<<30)).split('.')[0]+'.'+str(size*1.0/(1<<30)).split('.')[1][:2]+' GiB')
    elif size > 1<<20: #MB
        return (str(size*1.0/(1<<20)).split('.')[0]+'.'+str(size*1.0/(1<<20)).split('.')[1][:2]+' MiB')
    elif size > 1<<10: #KB
        return (str(size*1.0/(1<<10)).split('.')[0]+'.'+str(size*1.0/(1<<10)).split('.')[1][:2]+' KiB')
    else:
        return (str(size)+' Byte')



# def download_apk(sha256, filesize, save_path):
#     save_file = save_path
    
#     url = 'https://androzoo.uni.lu/api/download?apikey=' + AndroZooKey + '&sha256=' + sha256
#     last_byte = 0
#     reset_time = 0
#     print('Fetching %s\nFile size: %s' % (save_path, size2str(filesize)))
#     thread_size = filesize // thread_num
#     downloaded = 0
#     THREAD_POOL = []
#     for i in range(thread_num):
#         x = Thread(target=download_mt, args=(i*thread_size, (i+1)*thread_size, i, filesize, url, save_path))
#         THREAD_POOL.append(x)
#     for i in THREAD_POOL:
#         i.start()
#     for i in THREAD_POOL:
#         i.join()
#     print('Download Progress: 100%\t{}/{}'.format(size2str(filesize), size2str(filesize)))
#     print('Mixing Cache Files...')
#     try:
#         with open(save_file, 'wb') as sf:
#             for i in range(math.ceil(filesize/(single_size))):
#                 sf.seek(i*(single_size))
#                 tf_path = save_file + '-' + str(i)
#                 with open(tf_path, 'rb') as tf:
#                     sf.write(tf.read())
#                 os.remove(tf_path)
#     except Exception as e:
#         if reset_time < thread_num:
#             print('Mix cache files failed: {}'.format(e))
#             os.remove(save_file)
#             print('{} removed. Download failed.'.format(save_file))
#         else:
#             print('Reaching maximum reset time. Skipped.')
#             os.remove(save_file)
#         return False
#     else:
#         if reset_time >= thread_num:
#             print('Reaching maximum reset time. Skipped.')
#             os.remove(save_file)
#             return False
#         elif check_sha256(save_file, sha256):
#             print('Download Complete.')
#             return True
#         else:
#             print('File integrity check failed. Re-downloading...')
#             os.remove(save_file)
#             return False


def download_dsecription_googleplay(pkg_name):
    record = {'pkg_name':pkg_name, 'description': ''}
    try:
        response = requests.get(url='https://play.google.com/store/apps/details', params={'id':pkg_name}, proxies={'http':'http://127.0.0.1:20171','https':'http://127.0.0.1:20171'})
        html = etree.fromstring(response.text,etree.HTMLParser())
        des = html.xpath('//div[@data-g-id="description"]/text()')
        des = '\n'.join(des)
        # pp = html.xpath('//div[text()="Privacy policy"]/../div[@class="pSEeg"]/text()')
        # pp = '\n'.join(pp)
        if des and des != '':
            record['description'] = des
        # if pp and pp != '':
        #     record['privacy policy']=pp
        # result.append(record)
        # print(record)
        time.sleep(1)
    except BaseException as e:
        print(e)
    # finally:
        # if des and des != '':
        #     record['description']=des
        # if pp and pp != '':
        #     record['privacy policy']=pp
        # # result.append(record)
        # # print(record)
        # time.sleep(1)
    return record
# analyze_multi_sys(sys_pd)

# analyze_multi(pd)
# Read CSV to obtain pkgname and classification results


logging.getLogger("paramiko.transport").setLevel(logging.WARNING)

# SSH = paramiko.SSHClient()
# SSH.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# # SSH.set_log_channel()
# SSH.connect('172.25.76.45', port=22, username="admin11", password="Synology11")
# SFTP = SSH.open_sftp()
# print("opened")

def download_stfp(remote_path, remote_path2, local_path, sftp):
    if os.path.exists(local_path):
        return True
    
    # check SSH and SFTP
    try:
        try:
            sftp.get(remote_path, local_path)
        except:
            sftp.get(remote_path2, local_path)
    except Exception as err:
        print(f"failed due to: {err}")
        try:
            os.remove(local_path)
        except:
            pass
        return False
    
    return True

def check_phone():
    cate_result = pd.read_csv("/home/project/Documents/Car/Classification/Third_APP_Classification/result_new_dump_10000_to_159278.csv")
    androzoo = pd.read_csv("/home/project/Documents/Car/App description information on Google Play/latest.csv")
    new = []
    cnt = 0
    failed = []
    remove = []
    for idx, row in cate_result.iterrows():
        pkg_name = row['pkg_name']
        # skip
        # local_path = f"/home/sysu/Documents/Car/temp/{pkg_name}.apk"
        
        # if os.path.exists(local_path):
        #     continue
        # detect_path = result_path+pkg_name+"._result2.json"
        # if os.path.exists(detect_path):
        #         continue
        # Compare with Androzoo
        androzoo_row = androzoo[androzoo['pkg_name'] == pkg_name]
        # print(androzoo_row.keys())
        # print(androzoo_row)
        # print(androzoo_row)
        # if len(androzoo_row) > 1:
            # androzoo_row = androzoo_row.iloc[0]
        for i in range(len(androzoo_row)):
            tmp = androzoo_row.iloc[i]
            
            sha256 = tmp['sha256']
            vt_scan_date = tmp['vt_scan_date']
            vt_detection = tmp['vt_detection']
            apk_size = tmp['apk_size']
            try:
                vt_detection = int(vt_detection)
            except:
                continue
        
            year = vt_scan_date[:4]
            remote_path = f"Public/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
            remote_path2 = f"Public-2/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
            # local_path = f"/home/project/Documents/Car/temp/{pkg_name}.apk"
            local_path = f"/media/project/442E09A42E098FDA/Mobile_APP/{pkg_name}_{sha256}.apk"
            print(f"get: {remote_path}")
            
            if download_stfp(remote_path, remote_path2, local_path) == False:
                continue
            

            # analyze_single(local_path, f"{pkg_name}.apk")
            break

        print(idx)

# print(download_dsecription_googleplay('com.menesapps.senet2'))


def read_2():
    # 
    androzoo = pd.read_csv("/home/project/Documents/Car/App description information on Google Play/latest.csv")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect('172.25.76.45', port=22, username="admin11", password="Synology11")
    sftp = ssh.open_sftp()

    # new_update = []
    new_update = pd.read_csv("/home/project/Documents/Car/new.csv")
    # new_update = new_update.to_
    for idx, row in androzoo.iterrows():
        # only google play
        markets = row['markets']
        print(markets)
        if markets != 'play.google.com':
            continue

        # no existing results
        pkg_name = row['pkg_name']
        # skip
        local_path = f"/home/project/Documents/Car/temp/{pkg_name}.apk"
        if os.path.exists(local_path):
            continue
        detect_path = result_path+pkg_name+"._result2.json"
        if os.path.exists(detect_path):
                continue
        
        # Try downloading the description from Google Play
        ret = download_dsecription_googleplay(pkg_name)
        if ret['description'] == '':
            continue
        
        # Classify
        # It's best to classify them uniformly later

        # Download and check from Androzoo
        sha256 = row['sha256']
        vt_scan_date = row['vt_scan_date']
        vt_detection = row['vt_detection']
        apk_size = row['apk_size']
        try:
            vt_detection = int(vt_detection)
        except:
            continue

        year = vt_scan_date[:4]
        remote_path = f"Public/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
        remote_path2 = f"Public-2/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
        # local_path = f"/home/sysu/Documents/Car/temp/{pkg_name}.apk"
        print(f"get: {remote_path}")
        
        # try:
        #     # try:
        #     #     try:
        #     #         sftp.get(remote_path, local_path)
        #     #     except:
        #     #         sftp.get(remote_path2, local_path)
        #     # except:
        #     #     failed.append(row.to_dict())
        #     #     # if len(failed) != 0 and len(failed) % 100 == 0:
        #     #     json.dump(failed, open("/home/project/Documents/Car/temp/failed_analyse.json", "w"))
        #         # ok = download_apk(sha256, apk_size, local_path)
        #         # if not ok:
        #         #     continue
        #     download_single_pycurl(sha256, AndroZooKey, local_path)
        # except:
        #     print("continue")
        #     continue
        is_downloaded = download_single_pycurl(sha256, AndroZooKey, local_path)
        if is_downloaded is not True:
            print("continue")
            continue

        print(f"analyze_single {local_path}")
        analyze_single(local_path, f"{pkg_name}.apk")

        # delete app
        # try:
        #     os.remove(local_path)
        # except:
        #     pass

        # Save description information
        # new_update.append(
        new_item = {'pkg_name':ret['pkg_name'],
            'description':ret['description'],
            'sha256':sha256}
        # )
        # pd.DataFrame(new_update).to_csv("/home/project/Documents/Car/new.csv", index=False)
        # new_update.append()
        new_update.loc[len(new_update)] = new_item
        new_update.to_csv("/home/project/Documents/Car/new.csv", index=False)

    sftp.close()
    ssh.close()

    print(idx)


# check_phone()


androzoo = pd.read_csv("/home/project/Documents/Car/App description information on Google Play/latest.csv")
print("read androzoo")

def _down_thread(cate_result_split, num):
    print(f"_down_thread {num}")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # SSH.set_log_channel()
    ssh.connect('172.25.76.45', port=22, username="admin11", password="Synology11")
    sftp = ssh.open_sftp()
    print(f"sftp for thread {num} opened")

    for idx, row in cate_result_split.iterrows():
        pkg_name = row['pkg_name']
        # skip
        # local_path = f"/home/project/Documents/Car/temp/{pkg_name}.apk"
        
        # if os.path.exists(local_path):
        #     continue
        # detect_path = result_path+pkg_name+"._result2.json"
        # if os.path.exists(detect_path):
        #         continue
        # compare with androozoo
        androzoo_row = androzoo[androzoo['pkg_name'] == pkg_name]
        # print(androzoo_row.keys())
        # print(androzoo_row)
        # print(androzoo_row)
        # if len(androzoo_row) > 1:
            # androzoo_row = androzoo_row.iloc[0]
        for i in range(len(androzoo_row)):
            tmp = androzoo_row.iloc[i]
            
            sha256 = tmp['sha256']
            vt_scan_date = tmp['vt_scan_date']
            vt_detection = tmp['vt_detection']
            apk_size = tmp['apk_size']
            try:
                vt_detection = int(vt_detection)
            except:
                continue
        
            year = vt_scan_date[:4]
            remote_path = f"Public/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
            remote_path2 = f"Public-2/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
            # local_path = f"/home/project/Documents/Car/temp/{pkg_name}.apk"
            local_path = f"/media/project/442E09A42E098FDA/Mobile_APP/{pkg_name}_{sha256}.apk"
            print(f"get: {remote_path}")
            
            if download_stfp(remote_path, remote_path2, local_path, sftp) == False:
                continue
            # analyze_single(local_path, f"{pkg_name}.apk")
            

            
            break

        if idx % 10 == 0:
            time.sleep(2)

        print(idx)

    sftp.close()
    ssh.close()


def download_phone_multi(proc_num=5):
    cate_result = pd.read_csv("/home/project/Documents/Car/Classification/Mobile_APP_Classification/result_new_dump_10000_to_159278.csv")
    cate_idx_split = [i for i in range(0, len(cate_result), len(cate_result)//proc_num)]
    cate_idx_split.append(len(cate_result))
    cate_result_splits = [cate_result.loc[cate_idx_split[i]:cate_idx_split[i+1]-1] for i in range(len(cate_idx_split)-1)]

    p = multiprocessing.Pool(proc_num)
    for i in range(proc_num):
        p.apply_async(_down_thread, args=(cate_result_splits[i], i))
    p.close()
    # p.wait(60)
    # p.terminate()
    p.join()

    # new = []
    # cnt = 0
    # failed = []
    # remove = []
    # for idx, row in cate_result.iterrows():
    #     pkg_name = row['pkg_name']
    #     # skip
    #     # local_path = f"/home/project/Documents/Car/temp/{pkg_name}.apk"
        
    #     # if os.path.exists(local_path):
    #     #     continue
    #     # detect_path = result_path+pkg_name+"._result2.json"
    #     # if os.path.exists(detect_path):
    #     #         continue
    #     # compare with androozoo
    #     androzoo_row = androzoo[androzoo['pkg_name'] == pkg_name]
    #     print(androzoo_row.keys())
    #     print(androzoo_row)
    #     # print(androzoo_row)
    #     # if len(androzoo_row) > 1:
    #         # androzoo_row = androzoo_row.iloc[0]
    #     for i in range(len(androzoo_row)):
    #         tmp = androzoo_row.iloc[i]
            
    #         sha256 = tmp['sha256']
    #         vt_scan_date = tmp['vt_scan_date']
    #         vt_detection = tmp['vt_detection']
    #         apk_size = tmp['apk_size']
    #         try:
    #             vt_detection = int(vt_detection)
    #         except:
    #             continue
        
    #         year = vt_scan_date[:4]
    #         remote_path = f"Public/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
    #         remote_path2 = f"Public-2/AndroZoo/{year}/{vt_detection}/{sha256}.apk"
    #         # local_path = f"/home/project/Documents/Car/temp/{pkg_name}.apk"
    #         local_path = f"/media/project/442E09A42E098FDA/Mobile_APP/{pkg_name}_{sha256}.apk"
    #         print(f"get: {remote_path}")
            
    #         if download_stfp(remote_path, remote_path2, local_path) == False:
    #             continue
            

    #         # analyze_single(local_path, f"{pkg_name}.apk")
    #         break

    #     print(idx)

download_phone_multi(2)

# SFTP.close()
# SSH.close()
