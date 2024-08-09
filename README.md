# Mobile VS Vehicle APP
The script files for this project are mainly placed in three folders. The iArb_detection folder is mainly used for behavior detection of Android third-party libraries, the iArb_analysis folder is mainly used for behavior analysis of Android third-party libraries, and the Data_annotations folder is mainly used for data preprocessing and classification.

## iArb_detection

Client.py : This code implements a powerful command-line tool that allows users to parse AndrodManifest.xml files, decode resource files, decompile apks, extract apk package names, version codes, and version names, and output them in JSON format. Users can analyze apk files and dynamically track information of interest

Mobile_App_Detection_Script.py and Behavior_Detection.py : These two script files have implemented some detection for Android third-party apps, mobile apps, system apps, and car apps. The code includes some security measures such as memory checks and process management. Search for APK files through file processing and behavior checking (SHA256 hash value needs to be obtained to verify that the APK file has not been tampered with), and check the specified behaviors and API calls in the APK, generate behavior reports and log records of error messages. The sensitive API data list is a dataset obtained by reverse engineering in advance.

Automotive_APP_Behavior_Classification.py : This script file mainly defines the behavior of some ordinary APKs and special behaviors for in car applications, and classifies apps of different categories. By developing API call datasets and using dictionaries to record whether apps of different categories have specific behaviors.

## iArb_analysis

Mobile/Vehicle_APP_Behavior_Detection_Results_And_Category_Classification : Firstly, use the scripts in the iArb_detection folder to generate log information. Then, use these two script files (one for mobile applications and the other for in car applications) to calculate the proportion of 15 risk behaviors appearing in a certain category of apps, and create a table for output.

## Data_annotations

This script sends the collected package names and descriptions of the in car apps to the interface of the chatgpt model. The large model determines the category of the application, and the host parses the returned results and saves them.
