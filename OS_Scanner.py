import subprocess
import platform
import socket
import os
import psutil
import win32evtlog
import ctypes

print("Введите команду 'help' без кавычек для  просмотра краткой документации")
while True:
    
    user_input = input("Введите команду: ")
    if user_input == "tree":
        def display_file_system(path, indent=0):
            try:
                files = os.listdir(path)
            except PermissionError:
                print(' ' * indent + '[-] Access denied: ' + path)
                return

            for file in files:
                full_path = os.path.join(path, file)
                if os.path.isdir(full_path):
                    print(' ' * indent + '[+] ' + file)
                    display_file_system(full_path, indent + 4)
                else:
                    print(' ' * indent + '[-] ' + file)

        start_path = 'C:\\'
        display_file_system(start_path)

    elif user_input == "check_win":
        def is_windows_activated():
            try:
                key = ctypes.windll.wintrust.WTHelperProvDataFromStateData
                if key:
                    return True
                else:
                    return False
            except Exception:
                return False

        if is_windows_activated():
            print("Операционная система активирована.")
        else:
            print("Операционная система не активирована или это не Windows.")
        
    elif user_input == "stop":
        print("Сессия завершена")
        break
    elif user_input =="runn_services":
        
        services = psutil.win_service_iter()

        print('Запущенные сервисы:')
        for service in services:
            if service.status() == psutil.STATUS_RUNNING:
                print(service.name())
    elif user_input == "help":
        print('''
os - вид операционной системы
node - имя узла(рабочей группы или домена)
updates - информация про последние обновления
runn_services - запущенные сервисы
acc_policy - политика учетных записей
tree - файловая система
check_win - проверка активации ос
localhost - сетевые параметры
net_scan - сканирование портов
pass_policy - политика паролей
event_log - журнал событий
cipher - шифрование
audit - аудит информационной безопасности
stop - для выхода из программы
''')


    elif user_input == "os":
        os_name = platform.system()
        os_version = platform.release()
        print("Имя операционной системы:", os_name)
        print("Версия операционной системы:", os_version)
        

    elif user_input == "node":
        node_name = socket.gethostname()
        workgroup = socket.getfqdn().split('.', 1)[0]
        print("Имя узла:", node_name)
        print("Рабочая группа или домен:", workgroup)
    
    elif user_input == "updates":
        command1 = "Get-Hotfix | Select-Object -Property Description, InstalledOn | Sort-Object -Property InstalledOn -Descending"
        process1 = subprocess.Popen(["powershell", command1], stdout=subprocess.PIPE, shell=True)
        output1, error1 = process1.communicate()
        output1 = output1.decode("utf-8")
        print(output1)
        
    elif user_input == "acc_policy":
        command2 = "Get-LocalUser | Select-Object -Property Name, PasswordRequired, PasswordExpires, PasswordLastSet"
        process2 = subprocess.Popen(["powershell.exe", "-Command", command2], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        output2, error2 = process2.communicate()
        output2 = output2.decode("cp866")
        print(output2)

    

    elif user_input == "localhost":
        ip_address = socket.gethostbyname(socket.gethostname())
        ipconfig_process = subprocess.Popen(['ipconfig'], stdout=subprocess.PIPE, shell=True)
        output, _ = ipconfig_process.communicate()
        output = output.decode('cp866', errors='ignore')
        print('ipconfig output:')
        print(output)

    elif user_input == "net_scan":
        def scan_ports(target, start_port, end_port):
            print(f"Scanning ports on {target}...")
            for port in range(start_port, end_port + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1) 

                result = sock.connect_ex((target, port))
                if result == 0:
                    print(f"Port {port}: Open")
                else:
                    print(f"Port {port}: Closed")

                sock.close()

        target_host = input("Введите название хоста: ")
        start_port = 75
        end_port = 85

        
        scan_ports(target_host, start_port, end_port)
    elif user_input == "pass_policy":
        file_path = "passpol.txt"  
        with open(file_path, 'r') as file:
            file_content = file.read()
        print(file_content)

    #/////////////////////Дописать

    elif user_input == "event_log":

        def get_event_logs(log_name, num_records):
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            handle = win32evtlog.OpenEventLog(None, log_name)
            records = []
            total_records = 0

            while True:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events:
                    break

                for event in events:
                    if total_records >= num_records:
                        break

                    event_record = {}
                    event_record['RecordNumber'] = event.RecordNumber
                    event_record['TimeGenerated'] = event.TimeGenerated.Format()
                    event_record['EventID'] = event.EventID
                    event_record['EventType'] = event.EventType
                    event_record['SourceName'] = event.SourceName
                    event_record['Message'] = event.StringInserts

                    records.append(event_record)
                    total_records += 1

                if total_records >= num_records:
                    break

            win32evtlog.CloseEventLog(handle)

            return records
        event_logs = get_event_logs('Application', 10)
        for event in event_logs:
            print(f"RecordNumber: {event['RecordNumber']}")
            print(f"TimeGenerated: {event['TimeGenerated']}")
            print(f"EventID: {event['EventID']}")
            print(f"EventType: {event['EventType']}")
            print(f"SourceName: {event['SourceName']}")
            print(f"Message: {event['Message']}")
            print()

    elif user_input == "cipher":
        text = input("Введите текст, который хоитие зашифровавать: ")
        k = int(input("Укажите ключ: "))
        language = input("На каком языке текст, который вы ввели (русский, английский): ")


        def ceaser_cipher(user, key, lang):
            res, n = [], ""
            if lang.lower() == "русский" or lang.lower() == "russian":
                dictionary, dictionary_upper = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя", "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
            elif lang.lower() == "английский" or lang.lower() == "english":
                dictionary, dictionary_upper = "abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            else:
                return "Такого языка нет в опции"

            for i in range(len(user)):
                if user[i] in dictionary:
                    n = dictionary
                elif user[i] in dictionary_upper:
                    n = dictionary_upper
                else:
                    res.append(user[i])

                if user[i] in n:
                    for j in range(len(n)):
                        if 0 <= j + key < len(n) and user[i] == n[j]:
                            res.append(n[j + key])
                        elif j + key >= len(n) and user[i] == n[j]:
                            
                            res.append(n[(1 - j - key) % (len(n) - 1)])
                        
                        elif j + key < 0 and user[i] == n[j]:
                            res.append(n[(j + key) % len(n)])
            return ''.join(res)
        print(ceaser_cipher(text, k, language))


    elif user_input == "audit":
        def run_command(command):
            result = subprocess.run(command, capture_output=True, text=True)
            return result.stdout.strip()

        def check_firewall_status():
            command = ['netsh', 'advfirewall', 'show', 'allprofiles']
            output = run_command(command)
            if "State ON" in output:
                print("Брандмауэр включен для всех профилей.")
            else:
                print("Брандмауэр выключен или не настроен для всех профилей.")

        def check_antivirus_status():
            command = ['powershell', 'Get-MpComputerStatus']
            output = run_command(command)
            if "AMProductState : 397568" in output:
                print("Антивирус Windows Defender включен.")
            else:
                print("Антивирус Windows Defender выключен или не обновлен.")

        def check_windows_updates():
            command = ['powershell', 'Get-WindowsUpdate']
            output = run_command(command)
            if "IsInstalled : False" in output:
                print("Доступны новые обновления для установки.")
            else:
                print("Все доступные обновления уже установлены.")

        check_firewall_status()
        check_antivirus_status()
        check_windows_updates()




        














    

