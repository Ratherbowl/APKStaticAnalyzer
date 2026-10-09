from apk_info import APK

apk = APK("C:\\Users\\darda.LAPTOP-P9KGA7VP\\Downloads\\Test APK\\APKs\\com.adsb.apk\\ADSB+Flight+Tracker_38.3.3_apkcombo.com.xapk")
app_name = apk.get_application_name
main_activities = apk.get_main_activities()
min_sdk = apk.get_min_sdk_version()

print(f"Package Name: {app_name}")
print(f"Minimal SDK: {min_sdk}")