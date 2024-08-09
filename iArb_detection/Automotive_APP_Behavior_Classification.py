import pandas as pd
import os
import json

excel_path = "/home/project/Documents/Data/Automotive APP.xlsx"

report_dir_path = "/home/project/Documents/Analysis/Behavior_Detection/New_Automotive_Result"
remain_report_dir_path = "/home/project/Documents/Analysis/Behavior_Detection/Remaining_Automotive_Result"
    
d = pd.read_excel(excel_path)

BEHAVIOR_KEY = [
"Read Memory Card",
"Read Device Phone And Identification Status Information",
"Floating Window",
"Camera",
"Get Location Information",
"Get Bluetooth Matching Information",
"Read Wi-Fi Connection Records",
"Read Recording Records",
"Notification Pop Up",
"Advertisement Pop Up",
"Voice Calls",
"Music Playback",
"Video Playback",
"Video Calls",
"Network Access",
]

REMAIN_BEHAVIOR_KEY = [
"Read Contact",
"Read Call History",
"Read SMS",
"Read Schedule And To-Do List",
"Radar",
"Steering Wheel",
"Battery",
]

n = []
for idx, i in d.iterrows():
    t = i.to_dict()
    pkg_name = i['pkg_name']
    cates = i['cates']
    app_name = i['app_name']
    report_name = f"{pkg_name}.report.json"
    report = json.load(open(os.path.join(report_dir_path, report_name)))
    for key in BEHAVIOR_KEY:
        behavior = report.get(key)
        if behavior and len(behavior["apis"]) > 0:
            t[key] = 1
        else:
            t[key] = 0
    
    # M1，M2 represents one vehicle manufacturer
    for key in REMAIN_BEHAVIOR_KEY:
        if key == "Radar":
            a = ["M1 Acquire Front Radar", "M1 Acquire Back Radar"]
            for i in a:
                behavior = report.get(i)
                if behavior and len(behavior["apis"]) > 0:
                    t[key] = 1
                else:
                    t[key] = 0
        elif key == "Steering Wheel":
            b = ["M1 Obtain Steering Wheel Angle"]
            for i in b:
                behavior = report.get(i)
                if behavior and len(behavior["apis"]) > 0:
                    t[key] = 1
                else:
                    t[key] = 0
        elif key == "Battery":
            c = ["M1 Obtain Battery", "M2 Obtain Battery"]
            for i in c:
                behavior = report.get(i)
                if behavior and len(behavior["apis"]) > 0:
                    t[key] = 1
                else:
                    t[key] = 0
            
            

        else:
            behavior = report.get(key)
            if behavior and len(behavior["apis"]) > 0:
                t[key] = 1
            else:
                t[key] = 0
    n.append(t)

pd.DataFrame(n).to_excel("/home/project/Documents/Data/Automotive2 APP.xlsx")