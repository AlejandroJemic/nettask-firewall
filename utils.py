import json
import os 
import re
import threading

stop_event = threading.Event()

OUTPUT_DIR = "\\NetTask\\"
html_file = 'Connections.html'
port = 8090
BLOCK_LIST_FILE = 'blocklist.json'
WATCHDOG_LIST_FILE = 'watchdoglist.json'

def get_desktop_path():
    import os
    import ctypes
    # Obtener el directorio del escritorio del usuario actual
    csidl_desktop = 0x0010  # CSIDL_DESKTOP
    buf = ctypes.create_unicode_buffer(260)
    ctypes.windll.shell32.SHGetFolderPathW(None, csidl_desktop, None, 0, buf)
    return buf.value

def islocalhost(ip):
    import ipaddress
    if ip.startswith("["):
        return True
    try: ip_obj = ipaddress.ip_address(ip)
    except ValueError: return False

     # Verificar si es localhost en IPv4
    if ip_obj == ipaddress.IPv4Address('0.0.0.0') or ip_obj == ipaddress.IPv4Address('127.0.0.1'):
        return True

    # Verificar si es localhost en IPv6
    if ip_obj == ipaddress.IPv6Address('::') or ip_obj == ipaddress.IPv6Address('::1'):
        return True
    
    private_networks = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16')
    ]
    private_networks_ipv6 = [
        ipaddress.ip_network('fd00::/8'),  # Unique Local Address (ULA)
        ipaddress.ip_network('fe80::/10')  # Link-Local Unicast
    ]
    for network in private_networks + private_networks_ipv6:
        if ip_obj in network:
            return True
    exeptions_list = ["192.168.1", "fd00::", "fe80::", "[", "]"]
    if any(exep_string in ip for exep_string in exeptions_list):
        return True
    
    return False


def insert_line_in_file(file_path, line, index=None):
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        return
    with open(file_path, 'r',  encoding='utf-8') as file:
        lines = file.readlines()
    if index is None:
        lines.append(line + '\n')
    elif index == 0:
        lines.insert(0, line + '\n')
    else:
        lines.insert(min(index, len(lines)), line + '\n')
    with open(file_path, 'w',  encoding='utf-8') as file:
        file.writelines(lines)



def update_html_file():
    filename = get_desktop_path() + OUTPUT_DIR + html_file
    insert_line_in_file(filename, '   </div>',0)
    insert_line_in_file(filename, '     <button id="analyticsButton" >Analisis</button>',0)
    insert_line_in_file(filename, '     <button id="summaryButton" >Resumen</button>',0)
    insert_line_in_file(filename, '     <button id="searchButton" >Buscar</button>',0)
    insert_line_in_file(filename, '     <input type="text"   id="searchBox" placeholder="Buscar...">',0)
    insert_line_in_file(filename, '   <div  id="searchContainer">',0)
    insert_line_in_file(filename, '   <h1 class="title">NETWORK TASK MONITOR</h1>',0)
    insert_line_in_file(filename, ' <body onload="setTimeout(function(){ location.reload(); }, 1 * 60000);">',0)
    insert_line_in_file(filename, ' </head>',0)
    insert_line_in_file(filename, '  <link href="https://fonts.googleapis.com/css2?family=Titillium+Web:ital,wght@0,200;0,300;0,400;0,600;0,700;0,900;1,200;1,300;1,400;1,600;1,700&display=swap" rel="stylesheet">',0)
    insert_line_in_file(filename, '  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',0)
    insert_line_in_file(filename, '  <link rel="preconnect" href="https://fonts.googleapis.com">',0)
    insert_line_in_file(filename, '   <link rel="stylesheet" href="/static/style.css">',0)
    insert_line_in_file(filename, '   <title>Net-Tasks</title>',0)
    insert_line_in_file(filename, '   <meta name="viewport" content="width=device-width, initial-scale=1.0">',0)
    insert_line_in_file(filename, '   <meta charset="UTF-8">',0)
    insert_line_in_file(filename, ' <head>',0)
    insert_line_in_file(filename, ' <html lang="es">',0)
    insert_line_in_file(filename, '<!DOCTYPE html>',0)

    insert_line_in_file(filename,' <script src="/static/script.js"></script>')
    insert_line_in_file(filename, '</body>')
    insert_line_in_file(filename, '</html>')

def limpiar_html():
    file_path = get_desktop_path() + OUTPUT_DIR + html_file
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        html_content_limpio = content.replace('<td>NaN</td>', '<td></td>')
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(html_content_limpio)


def modify_process_to_Tasks_query():
    file_path = get_desktop_path() + OUTPUT_DIR + html_file
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        return
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    pattern = r'<td>([\w\.]+) - ([\d]+)</td>'
    def replace_process(match):
        process = match.group(1)
        pid = match.group(2)
        return f'<td><a href="/task/?process={process}">{process} - {pid}</a></td>'
        
    modified_content = re.sub(pattern, replace_process, content)
    
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(modified_content)

    

def modyfy_ext_ip_to_dnschecker_link():
    file_path = get_desktop_path() + OUTPUT_DIR + html_file
    if not os.path.isfile(file_path):
        print(f"El archivo '{file_path}' no existe.")
        return
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    pattern = r'<td>([\d\.]+):([\d]+)</td>'
    def replace_ip(match):
        ip = match.group(1)
        port = match.group(2)
        if not islocalhost(ip):
            return f'<td><a href="https://dnschecker.org/ip-blacklist-checker.php?query={ip}">{ip}:{port}</a></td>'
        else:
            return match.group(0)
        
    modified_content = re.sub(pattern, replace_ip, content)
    
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(modified_content)


def modify_domain_to_DNSDumpster_link():
    file_path = get_desktop_path() + OUTPUT_DIR + html_file
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        return
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    pattern = r"<td>([a-zA-Z0-9.-]+\.[a-zA-Z0-9.-]+)</td>"

    def replace_link(match):
        domain = match.group(1)
        return f'<td><a href="https://dnsdumpster.com/"  onclick="copyDomain(\'{domain}\')">{domain}</a></td>'

    modified_content = re.sub(pattern, replace_link, content)

    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(modified_content)

def modify_google_maps_links():
    file_path = get_desktop_path() + OUTPUT_DIR + html_file
    if not os.path.isfile(file_path):
        print(f"File '{file_path}' does not exist.")
        return
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    pattern = r'<td>(https://www\.google\.com/maps\?q=([0-9.-]+),\s*([0-9.-]+))</td>'

    def replace_link(match):
        
        full_url = match.group(1)
        latitude = match.group(2)
        longitude = match.group(3)
        return f'<td><a href="{full_url}">{latitude}, {longitude}</a></td>'
    
    # Replace all matches in the content
    modified_content = re.sub(pattern, replace_link, content)
    
    # Write the updated content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(modified_content)

import pandas as pd
from plyer import notification

def showNotification(rule):
    # Mostrar una notificación
    notification.notify(
        title='Regla de Firewall Añadida',
        message=f'Se ha añadido una regla de bloqueo: {rule}',
        app_name='Mi Aplicación de Firewall',
        timeout=10  # Tiempo en segundos que la notificación estará visible
    )

def get_current_df():
    df_csv_file = get_desktop_path() + OUTPUT_DIR + 'current_df.csv' 
    df = pd.read_csv(df_csv_file)
    return df

def get_summary_df():
    df = get_current_df()
    process_dict = {}
    for _, row in df.iterrows():
        task = row['Task']
        process_name = task.split(" - ")[0] 
        pid = task.split(" - ")[1]  # Extraer PID del formato "executable - PID"
        
        from_ip_port = row['From'].rsplit(':', 1)[0]
        to_ip_port = row['To'].rsplit(':', 1)[0]

        if process_name not in process_dict:
            process_dict[process_name] = {}

        if pid not in process_dict[process_name]:
            process_dict[process_name][pid] = {'From': set(), 'To': set()}

        # Añadir la IP al set correspondiente
        process_dict[process_name][pid]['From'].add(from_ip_port)
        process_dict[process_name][pid]['To'].add(to_ip_port)

    # Convertir los sets a listas para facilitar la búsqueda
    for process_name, pids in process_dict.items():
        for pid, connections in pids.items():
            connections['From'] = list(connections['From'])
            connections['To'] = list(connections['To'])
    # return process_dict as json
    return process_dict

def query_by_process_name( process_name,df=None):
    df = get_current_df()
    df_filtered = df[df['Task'].str.contains(process_name)]
    return parse_sort_query(df_filtered)
# print(query_by_process_name(df, 'svchost.exe'))


def query_by_source_ip(df, source_ip):
    # Filtrar por IP de origen
    df_filtered = df[df['From'].str.startswith(source_ip)]
    return parse_sort_query(df_filtered)
# print(query_by_source_ip(df, '0.0.0.0'))

def query_by_dest_ip(df, dest_ip):
    # Filtrar por IP de destino
    df_filtered = df[df['To'].str.startswith(dest_ip)]
    return parse_sort_query(df_filtered)

def parse_sort_query(df_filtered):
    # Extraer PID
    df_filtered['PID'] = df_filtered['Task'].apply(lambda x: x.split('-')[-1].strip())
    # Separar IPs y Puertos
    df_filtered[['From_IP', 'From_Port']] = df_filtered['From'].str.extract(r'^(.*):([^:]*)$')
    df_filtered[['To_IP' ,'To_Port']] = df_filtered['To'].str.extract(r'^(.*):([^:]*)$')

    df_filtered['From_IP'] = df_filtered['From_IP'].fillna('')
    df_filtered['From_Port'] = df_filtered['From_Port'].fillna('')
    df_filtered['To_IP'] = df_filtered['To_IP'].fillna('')
    df_filtered['To_Port'] = df_filtered['To_Port'].fillna('')
    return df_filtered[['Time','Task', 'PID', 'From_IP', 'From_Port', 'To_IP', 'To_Port','CMD']].sort_values(by='Time', ascending=False)

def get_coincidences(df):
    try:
        count_df = df.groupby('Conection').size().reset_index(name='Count')
        repeated_connections = count_df[count_df['Count'] > 1]['Conection']
        tasks_dict = {}
        for conn in repeated_connections:
            tasks = df[df['Conection'] == conn]['Task'].tolist()
            tasks_dict[conn] = {
                'Count': count_df[count_df['Conection'] == conn]['Count'].values[0],
                'Tasks': tasks
            }
        print('repeated_connections', repeated_connections)
        print('tasks_dict', tasks_dict)
        return json.dumps(tasks_dict, indent=4)
    except Exception as e:
        print(f"Error en get_coincidences: {e}")
        return pd.DataFrame()  # Retornar un DataFrame vacío en caso de error


