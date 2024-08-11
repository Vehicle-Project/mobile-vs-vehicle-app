import os
import json
import pandas as pd

# D1-D9 represents one folder
pd_names = ["D1", "D2", "D3", "D4", "D5",
            "D6", "D7", "D8", "D9"]

path = "/home/project/Documents/Car/Classification/Car_APP_Classification/"
app_path = "/home/project/Documents/Car/Result/Third_APP_Result/"

new = []
cnt = 0
cnt2 = 0
for pd_name in pd_names:
    result_name = f"result_{pd_name}_0_to_-1.csv"
    result_path = os.path.join(path, result_name)
    result = pd.read_csv(result_path)
    result['pkg_name'] = result['pkg_name'].str.replace("package：", "")
    for idx, row in result.iterrows():
        pkg_name = row['pkg_name']
        if type(pkg_name) == 'float':
            continue

        cnt2 += 1
        detect_name = f"{pkg_name}.apk._result2.json"
        detect_path = os.path.join(app_path, detect_name)
        try:
            detect = json.load(open(detect_path))
        except:
            print(f"error {pkg_name}")
            continue

        keys = list(detect.keys())
        for key in keys:
            cate = detect[key]
            permissions = cate['permissions']
            apis = cate['apis']
            if len(apis) == 0:
                row[key] = 0
            else:
                row[key] = 1
        cnt += 1
        
print(cnt)
print(cnt2)






