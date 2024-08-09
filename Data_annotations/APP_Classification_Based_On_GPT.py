import pandas as pd 
import csv
import random
from openai import OpenAI 
import json
import re
import copy
import matplotlib.pyplot as plt
import os

def find_first_number(text):
    match = re.search(r'\d+', text)
    if match:
        return match.group()
    else:
        # !TODO: The value returned here should be the number where the Unknown class is located and needs to be changed
        return '22'


def process_cates_v4():
    """Used to handle v4 APP categories"""
    filename = "v4.xlsx"
    global fd
    fd = pd.read_excel(filename)
    # print(fd)
    # tmp = fd.to_dict()
    global CATE4
    CATE4 = {}
    for i in range(len(fd)):
        cates = fd['cates']
        desc = fd['desc']
        
        CATE4[f"{i+1}:{remove_chin(cates[i])}"] = desc[i]
    # print(CATE4)
        
    CATE4["21:Others"] = "other small categories can be categorized into this."
    CATE4["22:Unknown"] = "the descriptionfailed to contain enough data to categorize this app."
    print(CATE4)



def remove_chin(text):
    pattern = r'（[\u4e00-\u9fa5]+）'
    return re.sub(pattern, '', text)

process_cates_v4()


def categorize_single(pkg_name:str, description:str, cate):
    
    client = OpenAI(api_key="sk-M1c7ZswQRzLadwKz4e3689E02d654622Af1e86Ad1c8dE5D3", base_url="https://openkey.cloud/v1")
    
    results = []
        
    completion = client.chat.completions.create(
    model="gpt-3.5-turbo",
    messages=[
        {"role": "system", "content": f"categorize the given app, and give me only number: {cate},"},
        {"role": "user", "content": f"pkg name:{pkg_name}, description:{description}"}
    ],
    temperature=0.2
    )
    answer = completion.choices[0].message.content
    results.append(
        {'pkg_name':pkg_name,
        'description':description,
        'answer':answer
        }
    )

    print(answer, find_first_number(answer))
    return find_first_number(answer)


def categorize_multi(start=0, end=0, cate=CATE4, filename='new_dump',
                     path=''):
    if path != '':
        filepath = os.path.join(path, filename)
    else:
        filepath = filename

    samples = pd.read_csv(filepath+'.csv')  # s
    print(samples.keys())
    # reader2 = pd.read_csv("new_dump.csv")
    global results
    results = []
    global failed
    failed = []
    global result_name 
    result_name = f"result_{filename}_{start}_to_{end-1}.csv"
    global failed_name
    failed_name = f"failed_{filename}_{start}_to_{end-1}.csv"
    for idx, row in samples.iterrows():
        if start <= idx < end or (start == 0 and end == 0):
            try:
                pkg_name = row['pkg_name']
            except:
                pkg_name = row['app_name']
            try:
                description = row['description']
            except:
                description = row['app_info_eng']
            try:
                answer = categorize_single(pkg_name, description, cate)
            except:
                failed.append(pkg_name)
                answer = '22'
                print(f"failed at {idx}")
            results.append(
                {'pkg_name':pkg_name,
                'description':description,
                'answer':answer
                }
            )
            if idx % 1000 == 0:
                df = pd.DataFrame(results)
                df.to_csv(result_name, index=False)
                df2 = pd.DataFrame(failed)
                df2.to_csv(failed_name, index=False)
    df = pd.DataFrame(results)
    df.to_csv(result_name, index=False)
    df2 = pd.DataFrame(failed)
    df2.to_csv(failed_name, index=False)


def draw_chart(figure_name=None, result_name=None, title='', 
               show=True):
    results = pd.read_csv(result_name)
    # csv_writer = csv.DictWriter(open("results_cate_2.csv", "w", encoding='utf-8', newline=""), fieldnames=list(results[0].keys()))
    # csv_writer.writeheader()
    total = [0]*22
    # for idx, result in enumerate(results):
    for _, row in results.iterrows():
        result = row
        # print(result['answer'])
        if type(result['answer']) == str:
            number = int(find_first_number(result['answer']))
        elif type(result['answer']) == int:
            number = result['answer']
        try:
            total[number-1] += 1
        except:
            # print(f"error at number:{number}")
            # continue
            total[21] += 1

    import copy
    tmp = copy.deepcopy(fd['cates'])
    tmp[20] = 'Others'
    tmp[21] = 'Unknown'
    cate_label = []
    for _, label in enumerate(tmp):
        cate_label.append(remove_chin(label))
    print(cate_label) 
    labels = [f"{i+1}:{cate_label[i]}" for i in range(22)]
    print(total)
    plt.clf()
    plt.bar(labels, total)
    for idx, value in enumerate(total):
        plt.text(idx, value, str(value), ha='center')
    if title != '':
        plt.title(title)
    plt.xlabel("Categories")
    plt.xticks(rotation=90)
    
    plt.ylabel("Values")
    if figure_name is None:
        figure_name = f"fig_"
    assert type(figure_name) == str
    plt.savefig(figure_name)
    if show:
        plt.show()
    

# categorize_multi(0, 10000)
    
def categorize_car_apps():
    import os
    # !unused
    # CATE4_v2 = copy.deepcopy(CATE4)
    # del CATE4_v2['21:Others']
    # del CATE4_v2['22:Unknown']
    path = '/home/project/Documents/Car/APP_Information/'
    names = ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9']
    for _, name in enumerate(names):
        print(f"CATEGORIZING {name}\n")
        categorize_multi(0, 0, filename=name, path=path)

# categorize_car_apps()
        
def draw_chart_car_apps():
    names = ['D1', 'D2', 'D3', 'D4', 'D5', 'D6', 'D7', 'D8', 'D9']
    start = 0
    end = 0
    for name in names:
        result_name = f"result_{name}_{start}_to_{end-1}.csv"
        figure_name = f"fig_{name}_{start}_to_{end-1}"
        draw_chart(figure_name, result_name,
                   title=name, show=False)

# draw_chart_car_apps()

def update_car_apps():
    CATE4_v2 = copy.deepcopy(CATE4)
    del CATE4_v2['21:Others']
    del CATE4_v2['22:Unknown']

    names = [  # 'D1', 'D2',
               'D3',
               # 'D4', 'D5', 'D6', 'D7', 'D8', 'D9'
            ]
    start = 0
    end = 0
    path = '/home/project/Documents/Car/Classification/Car_APP_Classification/'
    new_path = '/home/project/Documents/Car/Classification/Car_APP_Classification2/'
    for name in names:
        result_name = f"result_{name}_{start}_to_{end-1}.csv"
        figure_name = f"fig_{name}_{start}_to_{end-1}"
        # failed_name = f"failed_{name}_{start}_to_{end-1}.csv"

        result = pd.read_csv(os.path.join(path, result_name))
        # result.copy()
        # failed = pd.read_csv(os.path.join(path, failed_name))
        result_no_21_22 = copy.deepcopy(result)
        # for row in failed.iterrows():
        for idx, row in result.iterrows():
            # pkg_name = row[1].iloc[0]
            # print(row)
            # row = row[1]
            if row['answer'] in [21, 22]:
                answer = categorize_single(
                    row['pkg_name'],
                    row['description'],
                    cate=CATE4_v2
                )
                # answer = 22
                result_no_21_22.at[idx, 'answer'] = int(answer, 10)
                # print(result_no_21_22.at[idx,'answer'])
        # return result_no_21_22
        result_no_21_22.to_csv(result_name)
            # tmp = result[result['pkg_name']==pkg_name]
            # print(tmp) 
    # return failed
        

# categorize_multi(10000, 159279)
        
# draw_chart(figure_name="fig_new_dump_10000_to_159278",
#            result_name="result_new_dump_10000_to_159278.csv",
#            title="all samples",
#            show=True)

# def update_failed(name="failed_new_dump_10000_to_159278.csv"):
#     failed = pd.read_csv(name)
#     all = pd.read_csv("new_dump.csv")



