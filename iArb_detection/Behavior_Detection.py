from androguard.misc import AnalyzeAPK
from androguard.core.analysis.analysis import Analysis, ClassAnalysis, MethodAnalysis

from loguru import logger
logger.remove()
import os
import json
import gc
import subprocess
import threading
import psutil
import multiprocessing
import time
import hashlib
import re

proj_path = "/home/project/Documents"
parent_path = os.path.join(proj_path, "Data/APP")
apkid_dir_path = os.path.join(proj_path, "Analysis/APKID_Result")
report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Third_APP_Result")
log_path = os.path.join(proj_path, "log.log")
failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Third_APP_Detection_Failure.log")

mobile_app_dir_path = "/media/project/442E09A42E098FDA/Mobile_APP"
mobile_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Mobile_APP_Result")
mobile_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Mobile_APP_Detection_Failure.log")

sys_app_dir_path = os.path.join(proj_path, "Data/System_APP")
sys_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/System_APP_Result")
sys_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/System_APP_Detection_Failure.log")

soot_path = "/home/project/Documents/Script/Soot_Detect_Script/soot"
soot_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Third_APP_Soot_Result")
soot_mobile_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Mobile_APP_Soot_Result")
soot_sys_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/System_APP_Soot_Result")
soot_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Third_APP_Soot_Detection_Failure.log")
soot_mobile_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Mobile_APP_Soot_Detection_Failure.log")
soot_sys_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/System_APP_Soot_Detection_Failure.log")

remain_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Third_APP_Remain_Result")
remain_mobile_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Mobile_APP_Remain_Result")
remain_sys_report_dir_path = os.path.join(proj_path, "Analysis/Behavior_Detection/System_APP_Remain_Result")
remain_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Third_APP_Remain_Detection_Failure.log")
remain_mobile_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/Mobile_APP_Remain_Detection_Failure.log")
remain_sys_failed_report_path = os.path.join(proj_path, "Analysis/Behavior_Detection/System_APP_Remain_Detection_Failure.log")


ANALYZE_NORMAL = False
ANALYZE_SOOT = False
ANALYZE_REMAIN = True

assert os.path.exists(proj_path)
assert os.path.exists(parent_path)
assert os.path.exists(apkid_dir_path)
assert os.path.exists(report_dir_path)
assert os.path.exists(mobile_app_dir_path)

import logging
# Create a logger（Logger）
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create a FileHandler to write logs to a file
file_handler = logging.FileHandler(log_path)
file_handler.setLevel(logging.DEBUG)

# Create a console processor (StreamHandler) to output logs to the console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Create a formatter
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Add the log renderer to the processor
file_handler.setFormatter(formatter)
console_handler.setFormatter(formatter)

# Add the processor to the logger
logger.addHandler(file_handler)
logger.addHandler(console_handler)

INTERVAL = 5
THRESHOLD = 80

# 22

# 15
BEHAVIORS = [
    ["Read SD Card", ["READ_EXTERNAL_STORAGE"], [
        ["Landroid/os/Environment;", "getExternalStorageDirectory"],
        ["Landroid/os/Environment;", "getExternalStoragePublicDirectory"],
        ["Landroid/content/Context;", "getExternalFilesDir"],
    ]],
    ["Read phone state and device ID", ["READ_PHONE_STATE"], [
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
    ["Access Camera", ["CAMERA"], [
        ["Landroid/hardware/Camera;", "takePicture"],
        ["Landroid/hardware/Camera;", "open"],
        ["Landroid/media/MediaRecorder;", "start"],
        ["Landroid/hardware/camera2/CameraManager;", "openCamera"],
        ["Landroid/hardware/Camera;", "startPreview"]
    ]],
    ["Read location", ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"], [
        ["Landroid/location/LocationManager;", "getLastKnownLocation"],
        ["Landroid/location/LocationManager;", "requestLocationUpdates"],
        ["Landroid/location/LocationListener;", "onLocationChanged"],
        ["Landroid/location/Location;", "getLatitude"],
        ["Landroid/location/Location;", "getLongitude"],
        ["Landroid/location/Location;", "getAltitude"],
    ]],
    ["Read bluetooth pairing", ["BLUETOOTH"], [
        ["Landroid/bluetooth/BluetoothAdapter;", "getBondedDevices"],
        ["Landroid/bluetooth/BluetoothDevice;", "getName"],
        ["Landroid/bluetooth/BluetoothDevice;", "getAddress"],
        ["Landroid/bluetooth/BluetoothDevice;", "getBondState"],
    ]],
    ["Read Wi-Fi connection records", ["ACCESS_WIFI_STATE"], [
        ["Landroid/net/wifi/WifiManager;", "getConfiguredNetworks"],
        ["Landroid/net/wifi/WifiManager;", "getConnectionInfo"],
        ["Landroid/net/wifi/WifiInfo;", "getSSID"],
        ["Landroid/net/wifi/WifiInfo;", "getBSSID"],
        ["Landroid/net/wifi/WifiInfo;", "getIpAddress"],
    ]],
    ["Read recordings", ["RECORD_AUDIO"], [
        ["Landroid/media/MediaRecorder;", "setAudioSource"],
        ["Landroid/media/MediaRecorder;", "setOutputFormat"],
        ["Landroid/media/MediaRecorder;", "setAudioEncoder"],
        ["Landroid/media/MediaRecorder;", "setOutputFile"],
        ["Landroid/media/MediaRecorder;", "prepare"],
        ["Landroid/media/MediaRecorder;", "start"],
        ["Landroid/media/MediaRecorder;", "stop"],
    ]],
    ["Notification pop-up", ["POST_NOTIFICATIONS"], [
        ["Landroid/app/NotificationManager;", "notify"],
        ["Landroid/app/Notification/Builder;", "setSmallIcon"],
        ["Landroid/app/Notification/Builder;", "setContentTitle"],
        ["Landroid/app/Notification/Builder;", "setContentText"],
        ["Landroid/app/Notification/Builder;", "setPriority"],
        ["Landroid/app/Notification/Builder;", "setAutoCancel"],
    ]],
    ["Advertisement pop-up", ["INTERNET", "ACCESS_NETWORK_STATE"], [
        ["Lcom/adnetwork/sdk/AdRequest;", "loadAd"],
        ["Lcom/adnetwork/sdk/AdRequest;", "setAdListener"],
        ["Lcom/adnetwork/sdk/InterstitialAd;", "show"],
        ["Lcom/adnetwork/sdk/AdView;", "setAdSize"],
        ["Lcom/adnetwork/sdk/AdView;", "setAdUnitId"],
        ["Lcom/adnetwork/sdk/AdListener;", "onAdLoaded"],
        ["Lcom/adnetwork/sdk/AdListener;", "onAdFailedToLoad"],
    ]],
    ["Voice call", ["CALL_PHONE"], [
        ["Landroid/telephony/TelephonyManager;", "listen"],
        ["Landroid/telephony/TelephonyManager;", "endCall"],
        ["Landroid/telephony/TelecomManager;", "placeCall"],
        ["Landroid/telephony/PhoneStateListener;", "onCallStateChanged"],
    ]],
    ["Audio playback", ["MEDIA_CONTENT_CONTROL", "WAKE_LOCK"], [
        ["Landroid/media/MediaPlayer;", "create"],
        ["Landroid/media/MediaPlayer;", "setDataSource"],
        ["Landroid/media/MediaPlayer;", "prepare"],
        ["Landroid/media/MediaPlayer;", "start"],
        ["Landroid/media/MediaPlayer;", "pause"],
        ["Landroid/media/MediaPlayer;", "stop"],
        ["Landroid/media/MediaPlayer;", "release"],
        ["Landroid/media/AudioManager;", "setStreamVolume"],
        ["Landroid/media/AudioManager;", "getStreamVolume"],
        ["Landroid/media/AudioAttributes$Builder;", "setContentType"],
        ["Landroid/media/AudioAttributes$Builder;", "setUsage"],
    ]],
    ["Video playback", ["INTERNET", "ACCESS_WIFI_STATE"], [
        ["Landroid/media/MediaPlayer;", "setVideoScalingMode"],
        ["Landroid/media/MediaPlayer;", "setSurface"],
        ["Landroid/view/SurfaceView;", "setZOrderOnTop"],
        ["Landroid/view/SurfaceHolder;", "addCallback"],
        ["Landroid/widget/VideoView;", "setVideoURI"],
        ["Landroid/widget/VideoView;", "start"],
        ["Landroid/widget/VideoView;", "pause"],
        ["Landroid/widget/VideoView;", "stopPlayback"],
    ]],
    ["Video call", ["CAMERA", "RECORD_AUDIO", "INTERNET", "ACCESS_NETWORK_STATE", "MODIFY_AUDIO_SETTINGS"], [
        ["Landroid/net/sip/SipManager;", "makeAudioCall"],
        ["Landroid/net/sip/SipManager;", "makeVideoCall"],
        ["Landroid/net/sip/SipManager;", "setSpeakerMode"],
        ["Landroid/net/sip/SipAudioCall;", "start"],
        ["Landroid/net/sip/SipAudioCall;", "endCall"],
        ["Landroid/net/rtp/AudioStream", "setMode"],
        ["Landroid/net/rtp/AudioStream", "associate"],
        ["Landroid/net/rtp/AudioStream", "join"],
    ]],
    ["Access NIC", ["INTERNET"], [
        ["Ljava/net/HttpURLConnection;", "openConnection"],
        ["Ljava/net/HttpURLConnection;", "setRequestMethod"],
        ["Ljava/net/HttpURLConnection;", "getInputStream"],
        ["Ljava/net/HttpURLConnection;", "getOutputStream"],
        ["Lorg/apache/http/client/HttpClient;", "execute"],
        ["Landroid/net/http/AndroidHttpClient;", "newInstance"],
        ["Landroid/net/http/AndroidHttpClient;", "execute"],
        ["Lokhttp3/OkHttpClient;", "newCall"],
    ]],
]

def check_memory_usage(proc:multiprocessing.Process):
    while True:
        # Retrieve virtual memory information of the system
        virtual_memory = psutil.virtual_memory()
        used_memory_percent = virtual_memory.percent
        # Check if the memory usage exceeds the threshold
        if used_memory_percent > THRESHOLD:
            # Memory usage is too high, triggering other logic
            proc.terminate()
            return
        if proc.is_alive() == False:
            break
        time.sleep(INTERVAL)
        # Wait for a while and check again
    logger.info(f"[*] check_memory_usage: end.")
    return

def AnalyzeAPKMultiProc(full_file_path, report_path):
    logger.info(f"[*] AnalyzeAPKMultiProc: file:{full_file_path}")
    try:
        _apk, _dex, _dx = AnalyzeAPK(full_file_path)
    except:
        logger.error(f"[!] AnalyzeAPKMultiProc: failed in AnalyzeAPK with path:{full_file_path}")
        return
    
    # try:
    logger.info(f"[*] AnalyzeAPKMultiProc: check_apk: {full_file_path},\n\tresult at {report_path}")
    check_apk(_apk, _dex, _dx, full_file_path, report_path)
    # except:
        # logger.error(f"[!] AnalyzeAPKMultiProc: error in check_apk")



    del _dex
    del _dx
    del _apk
    gc.collect()

    logger.info(f"[*] AnalyzeAPKMultiProc: finished")
    return


def is_packed(path, dir_name):
    try:
        _, file = os.path.split(path)
        apkid_report_path = f"{os.path.join(os.path.join(apkid_dir_path, dir_name), file)}.json"
        os.system(f"apkid {path} -j > {apkid_report_path}")
        with open(apkid_report_path, "r") as jres:
            jobj = json.load(jres)

            for _file in jobj['files']:
                _matches = _file.get("matches")
                if _matches is None:
                    continue
                else:
                    _packer = _matches.get("packer")
                    if _packer and type(_packer) == list and len(_packer) >= 1:
                        logger.error(f"[!] analyze: find packer {_packer} in {path}")
                        return True
        return False
    except:
        return True
    

def check_behavior_remain(a, d, dx, behavior, permissions, apis, verbose=False):
    permission_results = []
    api_results = []
    for api in apis:
        class_name = api[0]
        method_name = api[1]
        for method in dx.find_methods(classname=class_name, methodname=method_name):
            if method.method.name == "<init>":
                continue
            for _, call, _ in method.get_xref_from():
                api_results.append((call.class_name, call.name, method.method.class_name, method.method.name))

    return permission_results, api_results


def check_apk_remain(apk_path, output_path):
    a, d, dx = AnalyzeAPK(apk_path)
    results = {}

    content_urls = {
        "content://call_log": ["Read call log", "READ_CALL_LOG"],
        "content://com.android.contacts": ["Read contacts", "READ_CONTACTS"],
        "content://com.android.calendar": ["Read calendar", "READ_CALENDER"],
        "content://sms": ["Read SMS", "READ_SMS"],
    }

    for s in dx.get_strings():
        s_value = s.get_value()
        matched_substrings = [s_key for s_key in content_urls.keys() if s_value.startswith(s_key)]
        if len(matched_substrings) > 0:
            behavior_key = content_urls[matched_substrings[0]][0]
            if behavior_key not in results:
                results[behavior_key] = 1
            else:
                results[behavior_key] += 1

    # M1，M2 represents one vehicle manufacturer
    behaviors = [
        ["M2 Acquire Power", [""], [
            ["Lcom/M2.*.ElectriPercentEventMsg", ".*"],
        ]],
        ["M2 Acquire Front Radar", [""], [
            ["Lcom/M2.*.CameraFrontRadarEventMsg", ".*"],
        ]],
        ["M2 Acquire Rear Radar", [""], [
            ["Lcom/M2.*.CameraTailRadarEventMsg", ".*"],
        ]],
        ["M2 Acquire Steering Wheel Angle", [""], [
            ["Lcom/M2.*.CameraSteerAngleEventMsg", ".*"],
        ]],
        ["M1 Acquire Power", [""], [
            ["Lcom/M1.*", "getEnergyOilLevelValue"],
        ]],
        ["M1 Acquire Gear Oil", [""], [
            ["Lcom/M1.*", "getGearBoxOilLevelValue"],
        ]],
        ["M1 Acquire Brake Fluid", [""], [
            ["Lcom/M1.*", "getBrakeFluidOilLevelValue"],
        ]],
    ]

    for behavior in behaviors:
        results[behavior[0]] = {}
        permissions, apis = check_behavior_remain(a, d, dx, behavior[0], behavior[1], behavior[2], True)
        results[behavior[0]]["permissions"] = permissions
        results[behavior[0]]["apis"] = apis

    with open(output_path, "w") as f:
        f.write(json.dumps(results, ensure_ascii=False))


def analyze_single_remain(apk_path, output_path):
    if os.path.exists(output_path):
        return True
    proc = multiprocessing.Process(target=check_apk_remain,
                                        args=(apk_path, output_path))
    memory_check = threading.Thread(target=check_memory_usage, args=(proc,))
    proc.start()
    memory_check.start()
    proc.join()
    memory_check.join(timeout=6)
    if os.path.exists(output_path):
        return True
    return False

def analyze_single_soot(input_path, output_path, timeout=1800):
    cmd = f"timeout {timeout}s java -jar {os.path.join(soot_path, 'check_behaviour-jar-with-dependencies.jar')} {os.path.join(soot_path, 'platforms')} {input_path} {output_path} "
    print(cmd)
    try:
        os.system(cmd)
    except:
        pass
    if os.path.exists(output_path):
        return True
    else:
        return False

def analyze_dir(dir_name):
    logger = logging.getLogger("analyze_car_apps")
    file_handler = logging.FileHandler(failed_report_path)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger2 = logging.getLogger("analyze_car_apps_soot")
    file_handler2 = logging.FileHandler(soot_failed_report_path)
    logger2.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger2.addHandler(file_handler2)

    logger3 = logging.getLogger("analyze_car_apps_remain")
    file_handler = logging.FileHandler(remain_failed_report_path)
    logger3.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger3.addHandler(file_handler)


    full_dir_path = os.path.join(parent_path, dir_name)
    files = os.listdir(full_dir_path)
    for file in files:
        
        full_file_path = os.path.join(full_dir_path, file)
        if os.path.isdir(full_file_path):
            continue
        if ".json" in file:
            continue

        logger.info(f"[*] analyze: start analyzing {file}")

        report_path = os.path.join(os.path.join(report_dir_path, dir_name), f"{file}.report.json")
        soot_report_path = os.path.join(os.path.join(soot_report_dir_path, dir_name), f"{file}.report.json")
        remain_report_path = os.path.join(os.path.join(remain_report_dir_path, dir_name), f"{file}.report.json")

        if os.path.exists(report_path) == False and ANALYZE_NORMAL:
            print(full_file_path, report_path)
            ret = analyze_single(full_file_path, report_path)
            if  ret == False:
                logger.debug(full_file_path)
        if os.path.exists(soot_report_path) == False and ANALYZE_SOOT:
            print(full_file_path, soot_report_path)
            soot_ret = analyze_single_soot(full_file_path, soot_report_path)
            if  soot_ret == False:
                logger2.debug(full_file_path)
        if os.path.exists(remain_report_path) == False and ANALYZE_REMAIN:
            print(full_file_path, remain_report_path)
            remain_ret = analyze_single_remain(full_file_path, remain_report_path)
            if  remain_ret == False:
                logger3.debug(full_file_path)
 

def analyze_single(full_file_path, report_path):
    if os.path.exists(report_path):
        return True

    proc = multiprocessing.Process(target=AnalyzeAPKMultiProc,
                                        args=(full_file_path, report_path))
    memory_check = threading.Thread(target=check_memory_usage, args=(proc,))
    proc.start()
    memory_check.start()

    logger.info(f"[*] analyze: join proc")
    proc.join()
    logger.info(f"[*] analyze: join memory_check")
    memory_check.join(timeout=6)

    if os.path.exists(report_path):
        return True
    return False


def analyze_multi(pathdir:list):
    for path in pathdir:
        logger.info(f"[*] analyze: analyzing dir:{path}")
        analyze_dir(path)



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
    a, d, dx = AnalyzeAPK(apk_path)
    results = {}
    for i in range(len(BEHAVIORS)):
        behavior = BEHAVIORS[i]
        results[behavior[0]] = {}
        permissions, apis = check_behavior(a, d, dx, behavior[0], behavior[1], behavior[2], True)
        results[behavior[0]]["permissions"] = permissions
        results[behavior[0]]["apis"] = apis

    with open(output_path, "w", encoding='utf-8') as f:
        f.write(json.dumps(results, ensure_ascii=False))


def remove_apk_suffix(file_name):
    if file_name[-4:] == ".apk":
        return file_name[:-4]
    else:
        return file_name

def get_sha256(file_path):
    sha256_obj = hashlib.sha256()
    bo = open(file_path, 'rb').read()
    sha256_obj.update(bo)
    output = sha256_obj.hexdigest().zfill(64).upper()
    print(output)
    return output

def get_package_name(apk_path):
    try:
        cmd = f"aapt dump badging {apk_path}"
        output = subprocess.check_output(cmd, shell=True).decode("utf-8")
        pat = r"package: name='([\w.]*)'"
        pato = re.compile(pat)
        # print(pato.match(output).group(1))
        result = pato.match(output)
        return result.group(1)
        # print(output)
    except:
        # return None
        return None


def analyze_car_apps():
    dirs = os.listdir(parent_path)
    print(dirs)
    for dir_name in dirs:
        analyze_dir(dir_name)
        

def analyze_mobile_apps():
    logger = logging.getLogger("analyze_mobile_apps")
    file_handler = logging.FileHandler(mobile_failed_report_path)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger2 = logging.getLogger("analyze_mobile_apps_soot")
    file_handler2 = logging.FileHandler(soot_mobile_failed_report_path)
    logger2.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger2.addHandler(file_handler2)

    logger3 = logging.getLogger("analyze_mobile_apps_remain")
    file_handler = logging.FileHandler(remain_mobile_failed_report_path)
    logger3.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger3.addHandler(file_handler)

    apps = os.listdir(mobile_app_dir_path)
    print(len(apps))
    for app in apps:
        full_app_path = os.path.join(mobile_app_dir_path, app)

        report_path = os.path.join(mobile_report_dir_path, f"{app}.report.json")
        if os.path.exists(report_path) == False and ANALYZE_NORMAL:
            print(full_app_path, report_path)
            ret = analyze_single(full_app_path, report_path)
            if ret == False:
                logger.debug(full_app_path)
            
        soot_report_path = os.path.join(soot_mobile_report_dir_path, f"{app}.report.json")
        if os.path.exists(soot_report_path) == False and ANALYZE_SOOT:
            print(full_app_path, soot_report_path)
            ret2 = analyze_single_soot(full_app_path, soot_report_path)
            if ret2 == False:
                logger2.debug(full_app_path)

        remain_report_path = os.path.join(remain_mobile_report_dir_path, f"{app}.report.json")
        if os.path.exists(remain_report_path) == False and ANALYZE_REMAIN:
            print(full_app_path, remain_report_path)
            ret3 = analyze_single_remain(full_app_path, remain_report_path)
            if ret3 == False:
                logger3.debug(full_app_path)


def analyze_sys_apps():    
    logger = logging.getLogger("analyze_sys_apps")
    file_handler = logging.FileHandler(sys_failed_report_path)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger2 = logging.getLogger("analyze_sys_apps_soot")
    file_handler2 = logging.FileHandler(soot_sys_failed_report_path)
    logger2.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger2.addHandler(file_handler2)

    logger3 = logging.getLogger("analyze_sys_apps_remain")
    file_handler = logging.FileHandler(remain_sys_failed_report_path)
    logger3.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(message)s")
    file_handler.setFormatter(formatter)
    logger3.addHandler(file_handler)


    vendors = os.listdir(sys_app_dir_path)
    for vendor in vendors:
        app_dir = os.path.join(os.path.join(sys_app_dir_path, vendor), 'app')
        apps = os.listdir(app_dir)
        for app in apps:
            app_path = os.path.join(app_dir, app)
            if os.path.isdir(app_path):
                _files = os.listdir(app_path)
                for _file in _files:
                    if _file.endswith(".apk"):
                        true_app_path = os.path.join(app_path, _file)
            elif os.path.isfile(app_path) and app.endswith(".apk"):
                true_app_path = app_path
            else:
                continue

            # analyze
            sha256 = get_sha256(true_app_path)
            report_path = os.path.join(
                os.path.join(os.path.join(sys_report_dir_path, vendor), 'app'), 
                f"{remove_apk_suffix(app)}_{sha256}.apk.report.json")
            soot_report_path = os.path.join(
                os.path.join(os.path.join(soot_sys_report_dir_path, vendor), 'app'), 
                f"{remove_apk_suffix(app)}_{sha256}.apk.report.json")
            remain_report_path = os.path.join(
                os.path.join(os.path.join(remain_sys_report_dir_path, vendor), 'app'), 
                f"{remove_apk_suffix(app)}_{sha256}.apk.report.json")
            
            if os.path.exists(report_path) == False and ANALYZE_NORMAL:
                print(true_app_path, report_path)
                ret = analyze_single(true_app_path, report_path)
                if ret == False:
                    logger.debug(true_app_path)

            if os.path.exists(soot_report_path) == False and ANALYZE_SOOT:
                print(true_app_path, soot_report_path)
                ret2 = analyze_single_soot(true_app_path, soot_report_path)
                if ret2 == False:
                    logger2.debug(true_app_path)

            if os.path.exists(remain_report_path) == False and ANALYZE_REMAIN:
                print(true_app_path, remain_report_path)
                ret3 = analyze_single_remain(true_app_path, remain_report_path)
                if ret3 == False:
                    logger3.debug(true_app_path)

        priv_app_dir = os.path.join(os.path.join(sys_app_dir_path, vendor), 'priv-app')
        try:
            priv_apps = os.listdir(priv_app_dir)
        except:
            print(f"Error open dir: {priv_app_dir}")
            continue
        for priv_app in priv_apps:
            priv_app_path = os.path.join(priv_app_dir, priv_app)
            if os.path.isdir(priv_app_path):
                _files = os.listdir(priv_app_path)
                # true_app_path = []
                for _file in _files:
                    if '.apk' in _file:
                        true_priv_app_path = os.path.join(priv_app_path, _file)
            elif os.path.isfile(priv_app_path) and '.apk' in priv_app:
                true_priv_app_path = priv_app_path
            else:
                continue

            # analyze
            sha256 = get_sha256(true_priv_app_path)
            report_path = os.path.join(
                os.path.join(os.path.join(sys_report_dir_path, vendor), 'priv-app'), 
                f"{remove_apk_suffix(priv_app)}_{sha256}.apk.report.json")
            soot_report_path = os.path.join(
                os.path.join(os.path.join(soot_sys_report_dir_path, vendor), 'priv-app'), 
                f"{remove_apk_suffix(priv_app)}_{sha256}.apk.report.json")
            remain_report_path = os.path.join(
                os.path.join(os.path.join(remain_sys_report_dir_path, vendor), 'priv-app'), 
                f"{remove_apk_suffix(priv_app)}_{sha256}.apk.report.json")
            
            if os.path.exists(report_path) == False and ANALYZE_NORMAL:
                print(true_priv_app_path, report_path)
                ret = analyze_single(true_priv_app_path, report_path)
                if ret == False:
                    logger.debug(true_priv_app_path)

            if os.path.exists(soot_report_path) == False and ANALYZE_SOOT:
                print(true_priv_app_path, soot_report_path)
                ret2 = analyze_single_soot(true_priv_app_path, soot_report_path)
                if ret2 == False:
                    logger2.debug(true_priv_app_path)

            if os.path.exists(remain_report_path) == False and ANALYZE_REMAIN:
                print(true_priv_app_path, remain_report_path)
                ret3 = analyze_single_remain(true_priv_app_path, remain_report_path)
                if ret3 == False:
                    logger3.debug(true_priv_app_path)
    
def analyze_automotive_apps():
    dir_path = "/home/project/Documents/AutomotiveAPP"
    report_dir_path = "/home/project/Documents/Analysis/Behavior_Detection/Automotive_Result"
    remain_report_dir_path = "/home/project/Documents/Analysis/Behavior_Detection/Automotive_remain_result"
    file_names = os.listdir(dir_path)
    for app, path in [(file_name[:-4], os.path.join(dir_path, file_name)) for file_name in file_names]:
        report_path = os.path.join(report_dir_path, f"{app}.report.json")
        remain_report_path = os.path.join(remain_report_dir_path, f"{app}.report.json")

        ret = analyze_single(path, report_path)
        remain_ret = analyze_single_remain(path, remain_report_path)
    
analyze_automotive_apps()