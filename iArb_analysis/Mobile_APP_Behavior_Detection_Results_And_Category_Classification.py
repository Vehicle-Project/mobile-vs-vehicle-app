import os
import pandas as pd
import json
import re
import copy
import matplotlib.pyplot as plt

MOBILE_OUTPUT_PATH = "/home/project/Documents/Analysis/Data/MOBILE_OUTPUT"
MOBILE_APPS_DESC_PATH = "/home/project/Documents/Analysis/Behavior_Detection/MOBILE_APPS_DESC.csv"
MOBILE_APPS_ANALYSES_PATH = "/home/project/Documents/Analysis/Behavior_Detection/MOBILE_APPS_ANALYSES"
MOBILE_OVERALL_PATH = "/home/project/Documents/Analysis/Overall Effectiveness/MOBLIE_OverallEffectiveness.csv"

CAR_OUTPUT_PATH = "/home/project/Documents/Analysis/Data/CAR_OUTPUT"
CAR_APPS_ANALYSES_PATH = "/home/project/Documents/Analysis/Behavior_Detection/CAR_APPS_ANALYSES"
CAR_APPS_DESC_PATH = "/home/project/Documents/Data/APP_Classification/CAR_APPS_DESC"
CAR_OVERALL_PATH = "/home/project/Documents/Analysis/Overall Effectiveness/Third_OverallEffectiveness.csv"

SYS_OUTPUT_PATH = "/home/project/Documents/Analysis/Cross_Result/SYS_OUTPUT"
SYS_APPS_ANALYSES_PATH = "/home/project/Documents/Analysis/Behavior_Detection/SYS_APPS_ANALYSES"
SYS_APPS_DESC_PATH = "/home/project/Documents/Data/APP_Classification/SYS_APPS_DESC.xlsx"
SYS_OVERALL_PATH = "/home/project/Documents/Analysis/Overall Effectiveness/SYS_OverallEffectiveness.csv"

TOTAL_OVERALL_PATH = "/home/project/Documents/Analysis/Overall Effectiveness/OverallEffectiveness.csv"
TOTAL_OVERALL_ORGANIZED_PATH = "/home/project/Documents/Analysis/Overall Effectiveness/OverallEffectiveness_Organized.csv"

CATE_PATH = "/home/project/Documents/script/v4.xlsx"

CATE = [
"Books",
"Photograph",
"Media & Vedio",
"Music & Audio",
"Games",
"Education",
"News",
"Business",
"Finance",
"Communication",
"Social",
"Transportation",
"Maps & Navigation",
"Shopping",
"Food & Drink",
"Travel & Local",
"Health & Fitness",
"House&Home",
"Tools",
"Events",
"Other",
"Unknown"
]

DETECTS = ['Read SD card', 'Read phone state and device ID', 'Floating window',
           'Access camera', 'Read location', 'Read bluetooth pairing',
           'Read Wi-Fi connection records', 'Read recordings', 'Notification pop-up', 'Advertisement pop-up',
           'Voice call', 'Audio playback', 'Video playback', 'Video call', 'Access NIC']

MULTI_USERS = ['Read SD card', 'Read phone state and device ID',
               'Read location', 'Read bluetooth pairing', 'Read Wi-Fi connection records',
               'Read recordings']

MULTI_STATUS = ['Floating window', 'Notification pop-up', 'Advertisement pop-up', 'Voice call', 'Audio playback',
               'Video playback',  'Access NIC']

MULTI_DEVICES = ['Access NIC', 'Access camera']

REMAIN_DETECTS = ["Read contacts", "Read call log", "Read SMS", "Read calendar",]


# M1，M2 represents one vehicle manufacturer
REMAIN_CAR_DETECTS = ["M2 Acquire Power", "M2 Acquire Front Radar", "M2 Acquire Rear Radar",
                      "M2 Acquire Steering Wheel Angle", "M1 Acquire Power", "M1 Acquire Gear Oil",
                      "M1 Acquire Brake Fluid"]

THREAT_LEVEL_MAP = {'Read SD card': 5.46, 'Read phone state and device ID': 5.22,
                    'Read call log': 5.56, 'Read contacts': 5.54, 'Read calendar': 4.34,
                    'Read SMS': 5.36, 'Read location': 5.32, 'Read bluetooth pairing': 4.48,
                    'Read Wi-Fi connection records': 4.44, 'Read recordings': 5.6, 'Advertisement pop-up': 5.8,
                    'Notification pop-up': 5.4, 'Floating window': 2.86, 'Audio playback': 2.82, 'Video playback': 5.3,
                    'Video call': 5.08, 'Voice call': 4.02, 'Access camera': 4.74, 'Access NIC': 4.66,
                    'Access lidar sensor ': 4.62, 'Access radar': 4.76, 'Access millimeter wave sensor ': 4.46,
                    'Access battery sensor ': 4.22, 'Access speed sensor ': 4.08, 'Access steering Wheel Sensor ': 4.32}



def relu(num):
    if num > 0:
        return 1
    else:
        return 0

def relu_threat_level(num, detect):

    if num > 0:
        return THREAT_LEVEL_MAP[detect]
    else:
        return 0


def relu_threat_level_df(df, detect):
    df_copy = df.copy()
    for idx, num in enumerate(df):
        if num > 0:
            df_copy[idx] = THREAT_LEVEL_MAP[detect]
        else:
            df_copy[idx] = 0.0
    return df_copy


def gen_mobile_app_rating_cate():
    analyses_paths = [os.path.join(MOBILE_APPS_ANALYSES_PATH, file) for file in os.listdir(MOBILE_APPS_ANALYSES_PATH)]
    analyses_map = {}
    for analyses_path in analyses_paths:
        report = json.load(open(analyses_path))
        detects = ['Read SD card', 'Read phone state and device ID', 'Floating window',
                   'Access camera', 'Read location', 'Read bluetooth pairing',
                   'Read Wi-Fi connection records', 'Read recordings', 'Notification pop-up', 'Advertisement pop-up',
                   'Voice call', 'Audio playback', 'Video playback', 'Video call', 'Access NIC']
        m = {}
        for idx, detect in enumerate(detects):
            num = len(report[detect]['apis'])
            m[detect] = relu(num)
        analyses_map[os.path.basename(analyses_path)] = m

    desc = pd.read_csv(MOBILE_APPS_DESC_PATH)
    for idx, cate in enumerate(CATE):
        cidx = idx + 1
        result = desc[desc['answer'] == cidx]

        new_output = []
        for _, row in result.iterrows():
            name = f"{row['pkg_name']}_{row['sha256']}.apk.report.json"
            m = analyses_map[name]
            tmp = {
                "pkg_name": row['pkg_name'],
                "sha256": row["sha256"],
                "description": row['description'],
            }
            tmp.update(m)
            new_output.append(tmp)
        pd.DataFrame(new_output).to_csv(os.path.join(MOBILE_OUTPUT_PATH, f"{CATE[idx]}.csv"),
                                        index=False)


def gen_car_app_rating_cate():
    """CAR APP"""
    # D1,D2... represents one apk collected by different paths
    dir_names = ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9"]
    sum_num = 0
    sum_analyses_num = 0
    sum_apks_num = 0
    for dir_name in dir_names:
        print(dir_name)

        dir_path = os.path.join(CAR_APPS_ANALYSES_PATH, dir_name)
        analyses_paths = [os.path.join(dir_path, file) for file in os.listdir(dir_path)]

        analyses_map = {}

        for analyses_path in analyses_paths:
            report = json.load(open(analyses_path))
            detects = ['Read SD card', 'Read phone state and device ID', 'Floating window',
                       'Access camera', 'Read location', 'Read bluetooth pairing',
                       'Read Wi-Fi connection records', 'Read recordings', 'Notification pop-up', 'Advertisement pop-up',
                       'Voice call', 'Audio playback', 'Video playback', 'Video call', 'Access NIC']
            m = {}
            for idx, detect in enumerate(detects):
                num = len(report[detect]['apis'])
                m[detect] = relu(num)
            analyses_map[os.path.basename(analyses_path)[:-81]] = m   # name_sha256.apk.report.json
        sum_analyses_num += len(analyses_map)

        desc = pd.read_csv(os.path.join(CAR_APPS_DESC_PATH, f"result_{dir_name}_0_to_-1.csv"))
        print("desclen:", len(desc))
        sum_apks_num += len(desc)
        sum = 0
        for idx, cate in enumerate(CATE):
            cidx = idx + 1
            result = desc[desc['answer'] == cidx]

            new_output = []
            for _, row in result.iterrows():
                try:
                    m = analyses_map[row['pkg_name']]
                except:
                    continue
                tmp = {
                    "pkg_name": row['pkg_name'],
                    # "sha256" : row["sha256"],
                    "description": row['description'],
                }
                tmp.update(m)
                new_output.append(tmp)
            t = os.path.join(CAR_OUTPUT_PATH, dir_name)
            try:
                os.mkdir(t)
            except:
                pass
            pd.DataFrame(new_output).to_csv(os.path.join(t, f"{CATE[idx]}.csv"),
                                            index=False)
            tmp_sum += len(new_output)
        print("matched:", tmp_sum)
        sum_num += tmp_sum
    print(sum_num)
    print(sum_analyses_num)
    print(sum_apks_num)


def read_analyses(analyses_paths):
    analyses_map = {}
    for analyses_path in analyses_paths:
        report = json.load(open(analyses_path))
        detects = ['Read SD card', 'Read phone state and device ID', 'Floating window',
                   'Access camera', 'Read location', 'Read bluetooth pairing',
                   'Read Wi-Fi connection records', 'Read recordings', 'Notification pop-up', 'Advertisement pop-up',
                   'Voice call', 'Audio playback', 'Video playback', 'Video call', 'Access NIC']
        m = {}
        for idx, detect in enumerate(detects):
            num = len(report[detect]['apis'])
            m[detect] = relu(num)
        analyses_map[os.path.basename(analyses_path)[:-81]] = m   # name_sha256.apk.report.json
    return analyses_map


def gen_sys_app_rating_cate():
    # M1,M2... represents one vehicle manufacturer
    dir_names = ["M1", "M2", "M3", "M4", "M5"]
    sum_num = 0
    sum_analyses_num = 0
    sum_apks_num = 0
    for dir_name in dir_names:
        dir_path = os.path.join(SYS_APPS_ANALYSES_PATH, dir_name)
        for d in ['app', 'priv-app']:
            dir_path2 = os.path.join(dir_path, d)
            try:
                analyses_paths = [os.path.join(dir_path2, file) for file in os.listdir(dir_path2)]
            except:
                continue

            analyses_map = read_analyses(analyses_paths)
            sum_analyses_num += len(analyses_map)

            sheet_name = f"{dir_name}_{d}"
            print(sheet_name)
            try:

                desc = pd.read_excel(SYS_APPS_DESC_PATH, sheet_name=sheet_name)
            except:
                continue
            print("desclen:", len(desc))
            sum_apks_num += len(desc)
            tmp_sum = 0
            for idx, cate in enumerate(CATE):
                cidx = idx + 1
                result = desc[desc['cates'] == cate]

                new_output = []
                for _, row in result.iterrows():
                    try:
                        m = analyses_map[row['app_name']]
                    except:
                        continue
                    tmp = {
                        "pkg_name" : row['pkg_name'],
                        # "sha256" : row["sha256"],
                        # "description" : row['description'],
                    }
                    tmp.update(m)
                    new_output.append(tmp)
                t = os.path.join(SYS_OUTPUT_PATH, dir_name)
                try:
                    os.mkdir(t)
                except:
                    pass
                t = os.path.join(t, d)
                try:
                    os.mkdir(t)
                except:
                    pass
                pd.DataFrame(new_output).to_csv(os.path.join(t, f"{CATE[idx]}.csv"),
                                                index=False)
                tmp_sum += len(new_output)
            print("matched:", tmp_sum)
            sum_num += tmp_sum

    print(sum_num)
    print(sum_analyses_num)
    print(sum_apks_num)


def process_shafa():
    result = pd.read_csv("/home/project/Documents/Data/APP_Classification/Car_APP/result_Sofa_0_to_-1.csv")
    result['pkg_name'] = result['pkg_name'].map(lambda x: x[:-33])
    print(result)
    result.to_csv("/home/project/Documents/Data/APP_Classification/Car_APP/result_Sofa_0_to_-1.csv")


def overall_effectiveness_mobile():
    a = []
    calc_num = {}
    for idx, cate in enumerate(CATE):
        r = {}
        r['cates'] = cate
        cidx = idx + 1
        report_cate = pd.read_csv(os.path.join(MOBILE_OUTPUT_PATH, f"{cate}.csv"))
        # Used to calculate the number of apps in each category
        if not calc_num.get(cate):
            calc_num[cate] = len(report_cate)
        else:
            calc_num[cate] += len(report_cate)

        m = {}
        # If any behavior exists, set it to 1
        report_cate['any_exist'] = 0
        report_cate['threat_level'] = 0.0
        report_cate['multi_users'] = 0
        report_cate['multi_status'] = 0
        report_cate['multi_devices'] = 0
        for detect in DETECTS:
            m[detect] = [report_cate[detect].sum(), len(report_cate)]
            report_cate['any_exist'] = report_cate['any_exist'] | report_cate[detect]
            report_cate['threat_level'] += relu_threat_level_df(report_cate[detect], detect)

            if detect in MULTI_USERS:
                report_cate['multi_users'] |= report_cate[detect]
            if detect in MULTI_STATUS:
                report_cate['multi_status'] |= report_cate[detect]
            if detect in MULTI_DEVICES:
                report_cate['multi_devices'] |= report_cate[detect]

        m['multi_users'] = [report_cate['multi_users'].sum(), len(report_cate)]
        m['multi_status'] = [report_cate['multi_status'].sum(), len(report_cate)]
        m['multi_devices'] = [report_cate['multi_devices'].sum(), len(report_cate)]
        report_cate['threat_level'] /= 15
        m['threat_level'] = [report_cate['threat_level'].sum(), len(report_cate)]
        m['any_exist'] = report_cate['any_exist'].sum()
        r.update(m)
        print(r)
        a.append(r)
    print(calc_num)
    return a


def overall_effectiveness_car():
    # D1,D2... represents one apk collected by different paths
    dir_names = ["D1", "D2", "D3", "D4", "D5", "D6", "D7", "D8", "D9"]
    calc_num = {}
    t = []
    for dir_name in dir_names:
        a = []
        for idx, cate in enumerate(CATE):
            r = {}
            r['cates'] = cate
            cidx = idx+1
            try:
                report_cate = pd.read_csv(os.path.join(os.path.join(CAR_OUTPUT_PATH, dir_name), f"{cate}.csv"))
                # print(report_cate.keys())
                if not calc_num.get(cate):
                    calc_num[cate] = len(report_cate)
                else:
                    calc_num[cate] += len(report_cate)

                m = {}
                report_cate['any_exist'] = 0
                report_cate['threat_level'] = 0.0
                report_cate['multi_users'] = 0
                report_cate['multi_status'] = 0
                report_cate['multi_devices'] = 0
                for detect in DETECTS:
                    m[detect] = [report_cate[detect].sum(), len(report_cate)]
                    report_cate['any_exist'] = report_cate['any_exist'] | report_cate[detect]
                    report_cate['threat_level'] += relu_threat_level_df(report_cate[detect], detect)

                    if detect in MULTI_USERS:
                        report_cate['multi_users'] |= report_cate[detect]
                    if detect in MULTI_STATUS:
                        report_cate['multi_status'] |= report_cate[detect]
                    if detect in MULTI_DEVICES:
                        report_cate['multi_devices'] |= report_cate[detect]

                m['multi_users'] = [report_cate['multi_users'].sum(), len(report_cate)]
                m['multi_status'] = [report_cate['multi_status'].sum(), len(report_cate)]
                m['multi_devices'] = [report_cate['multi_devices'].sum(), len(report_cate)]

                report_cate['threat_level'] /= 15
                m['threat_level'] = [report_cate['threat_level'].sum(), len(report_cate)]
                m['any_exist'] = report_cate['any_exist'].sum()
                r.update(m)

            except:
                for detect in DETECTS:
                    r[detect] = [0, 0]

                r['threat_level'] = [0, 0]
                r['any_exist'] = 0
                r['multi_users'] = [0, 0]
                r['multi_status'] = [0, 0]
                r['multi_devices'] = [0, 0]


            print(cidx, r)
            a.append(r)
        if len(t) == 0:
            t = copy.deepcopy(a)
        else:
            for i1 in range(len(t)):
                for i2 in range(len(a)):
                    r1 = t[i1]
                    r2 = a[i2]
                    if r1['cates'] == r2['cates']:
                        # merge
                        for detect in DETECTS:
                            r1[detect][0] += r2[detect][0]
                            r1[detect][1] += r2[detect][1]
                        r1['threat_level'][0] += r2['threat_level'][0]
                        r1['threat_level'][1] += r2['threat_level'][1]
                        r1['any_exist'] += r2['any_exist']
                        r1['multi_users'][0] += r2['multi_users'][0]
                        r1['multi_users'][1] += r2['multi_users'][1]
                        r1['multi_status'][0] += r2['multi_status'][0]
                        r1['multi_status'][1] += r2['multi_status'][1]
                        r1['multi_devices'][0] += r2['multi_devices'][0]
                        r1['multi_devices'][1] += r2['multi_devices'][1]
                        t[i1] = r1
    print(calc_num)
    return t


def overall_effectiveness_sys():
    # M1,M2... represents one vehicle manufacturer
    dir_names = ["M1", "M2", "M3", "M4", "M5"]
    t = []
    calc_num = {}
    for dir_name in dir_names:
        dir_path = os.path.join(SYS_OUTPUT_PATH, dir_name)
        for d in ['app', 'priv-app']:
            dir_path2 = os.path.join(dir_path, d)

            a = []
            for idx, cate in enumerate(CATE):
                r = {}
                r['cates'] = cate
                cidx = idx+1
                try:
                    report_cate = pd.read_csv(os.path.join(dir_path2, f"{cate}.csv"))
                    if not calc_num.get(cate):
                        calc_num[cate] = len(report_cate)
                    else:
                        calc_num[cate] += len(report_cate)

                    m = {}
                    report_cate['any_exist'] = 0
                    report_cate['threat_level'] = 0.0
                    report_cate['multi_users'] = 0
                    report_cate['multi_status'] = 0
                    report_cate['multi_devices'] = 0
                    for detect in DETECTS:
                        m[detect] = [report_cate[detect].sum(), len(report_cate)]
                        report_cate['any_exist'] = report_cate['any_exist'] | report_cate[detect]
                        report_cate['threat_level'] += relu_threat_level_df(report_cate[detect], detect)

                        if detect in MULTI_USERS:
                            report_cate['multi_users'] |= report_cate[detect]
                        if detect in MULTI_STATUS:
                            report_cate['multi_status'] |= report_cate[detect]
                        if detect in MULTI_DEVICES:
                            report_cate['multi_devices'] |= report_cate[detect]

                    m['multi_users'] = [report_cate['multi_users'].sum(), len(report_cate)]
                    m['multi_status'] = [report_cate['multi_status'].sum(), len(report_cate)]
                    m['multi_devices'] = [report_cate['multi_devices'].sum(), len(report_cate)]

                    report_cate['threat_level'] /= 15
                    m['threat_level'] = [report_cate['threat_level'].sum(), len(report_cate)]
                    m['any_exist'] = report_cate['any_exist'].sum()

                    r.update(m)

                except:
                    for detect in DETECTS:
                        r[detect] = [0, 0]
                    r['threat_level'] = [0, 0]
                    r['any_exist'] = 0
                    r['multi_users'] = [0, 0]
                    r['multi_status'] = [0, 0]
                    r['multi_devices'] = [0, 0]
                print(cidx, r)
                a.append(r)
            t.append(a)
    tt = t[0]
    for i in range(1, 10):
        print(i)
        tt = merge(tt, t[i])
    print(calc_num)
    return tt


def merge(a1, a2):
    ret = copy.deepcopy(a1)
    for i1 in range(len(ret)):
        for i2 in range(len(a2)):
            r1 = ret[i1]
            r2 = a2[i2]
            if r1['cates'] == r2['cates']:
                # merge
                for detect in DETECTS:
                    r1[detect][0] += r2[detect][0]
                    r1[detect][1] += r2[detect][1]
                r1['threat_level'][0] += r2['threat_level'][0]
                r1['threat_level'][1] += r2['threat_level'][1]
                r1['any_exist'] += r2['any_exist']
                r1['multi_users'][0] += r2['multi_users'][0]
                r1['multi_users'][1] += r2['multi_users'][1]
                r1['multi_status'][0] += r2['multi_status'][0]
                r1['multi_status'][1] += r2['multi_status'][1]
                r1['multi_devices'][0] += r2['multi_devices'][0]
                r1['multi_devices'][1] += r2['multi_devices'][1]
                ret[i1] = r1
    return ret


def div(t):
    t2 = copy.deepcopy(t)
    for r in t:
        for detect in DETECTS:
            try:
                r[detect] = r[detect][0] / r[detect][1]
            except:
                r[detect] = 0

    return t


def overall_effectiveness_total():
    t_mobile = overall_effectiveness_mobile()
    t_car = overall_effectiveness_car()

    t_sys = overall_effectiveness_sys()

    t_final = merge(merge(t_mobile, t_car), t_sys)

    t_dived = div(t_final)

    pd.DataFrame(t_dived).to_csv(TOTAL_OVERALL_PATH, index=False)
    return t_dived


t_mobile = overall_effectiveness_mobile()
# t_car = overall_effectiveness_car()
# t_sys = overall_effectiveness_sys()
# t_final = merge(merge(t_mobile, t_car), t_sys)
# # t_dived = div(t_final)


def merge_cates(t):
    tt = t.copy()
    n = {detect : 0 for detect in DETECTS}
    print(n)
    sum = 0
    for row in tt:
        sum += row['Read Memory Card'][1]
        for detect in DETECTS:
            n[detect] += row[detect][0]
            print(row[detect][0])
    print(sum)
    for key in n:
        n[key] /= sum
    return n, sum


def action_3():
    t_mobile_no_cate, t_mobile_sum = merge_cates(t_mobile)
    t_car_no_cate, t_car_sum = merge_cates(t_car)
    t_sys_no_cate, t_sys_sum = merge_cates(t_sys)

    pd.DataFrame([t_sys_no_cate, t_car_no_cate, t_mobile_no_cate]).to_excel("action_3.xlsx")


def normalize(t):
    t_organized = t.copy()
    for row in t_organized:
        for detect in DETECTS:
            cate_num = row[detect][1]
            row[detect] = row[detect][0]
        row['Number Of Categories'] = cate_num
        row['threat_level'] = row['threat_level'][0] / row['threat_level'][1]
    return t_organized

# t_organized = normalize()

"""
The occurrence rate of a certain behavior in all categories of apps:
I directly operated on Excel
Accumulate the sequence of behaviors to obtain the total number of apps for a 
behavior divided by the total number of apps

The proportion of 15 risky behaviors appearing in a certain category of APP
any_exist
"""

def action_4():
    n = []
    for row in t_final:
        try:
            multi_users = row['multi_users'][0]/row['multi_users'][1]
        except:
            multi_users = 0
        try:
            multi_status = row['multi_status'][0]/row['multi_status'][1]
        except:
            multi_status = 0
        try:
            multi_devices = row['multi_devices'][0]/row['multi_devices'][1]
        except:
            multi_devices = 0
        n.append({
            'cates': row['cates'],
            'multi_users': multi_users,
            'multi_status': multi_status,
            'multi_devices': multi_devices
        })
    pd.DataFrame(n).to_csv("/home/project/Documents/Analysis/action_4.csv")


