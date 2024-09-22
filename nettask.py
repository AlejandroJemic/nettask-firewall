import ctypes
from io import StringIO
import json
import sys
import threading
import socket
import subprocess
import requests
import pandas as pd
import os
import time
import webbrowser
import utils as u
import winHandler as wh
from utils import stop_event
import firewallHandler as fh
from datetime import datetime
import psutil

# Definir códigos de color
class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

netstat_cmd = "netstat -ano"  # use  "netstat -ano -p tcp" for tcp traffic only
findstr_cmd = "findstr ESTABLISHED"
tasklist_cmd = "tasklist /fi"
csv_cmd = "/v /fo csv"
update =False
filename = 'Connections.xlsx'
isFirst = True
allowRulesCreation = False
allowLocalRules = False
df = None

columns = ["Time","Type","Conection","From","To","Task","Domain", "LatLon","Location", "Link", "State", "isBolcked", "CMD"]

def getNewRow():
    return {"Time": "", "Type": "", "Conection" : "","From":"","To":"",'Task': "",'Domain': "", 'LatLon': "",'Location': "", 'Link': "", "State": "", "isBolcked": "", "CMD": ""}


def netTask():
    dir = u.get_desktop_path() + u.OUTPUT_DIR
    if os.path.exists(dir + filename):
      df = pd.read_excel(dir + filename, index_col=None)
    else:
         df =pd.DataFrame(columns=columns, index=None)
    while True:
        update = False
        # Ejecutar el comando 'netstat'
        netstat_output = subprocess.check_output(netstat_cmd, shell=True).decode('ISO-8859-1')
        # Filtrar las conexiones establecidas

        established_connections, closed_connections = GetConnections(netstat_output)

        CloseConnetions(closed_connections)

        # Recorrer las conexiones y obtener el PID y el puerto
        for conn in established_connections:
            conection = ""
            row = getNewRow()
            #print(conn)
            protocol = conn[0]
            state =conn[3]
            pid = conn[4]
            conection = conn[1]  + " to " + conn[2]
            if not df['Conection'].isin([conection]).any():
                update = True
                ip = conn[2].split(":")[0]
                port = conn[2].split(":")[1]
                # Ejecutar el comando 'tasklist'
                tasklist_output = subprocess.check_output(f"{tasklist_cmd} \"PID eq {pid}\" {csv_cmd}", shell=True).decode('ISO-8859-1')
                # Filtrar el nombre del ejecutable
                executable = [line.split(",")[0].strip('"') for line in tasklist_output.splitlines() if line.strip()]
                print(f"{Colors.CYAN}FIND NEW CONNECTION {conn} FOR {Colors.RED} {executable[1]} {Colors.RESET}")

                # Imprimir los resultados
                if executable:
                    row["Conection"] =  conn[1]  + " to " + conn[2]
                    row["Time"] = datetime.now().strftime("%d/%m %H:%M")
                    row["Type"] = protocol
                    row['From'] = conn[1]
                    row['To'] =  conn[2]
                    row['Task'] =executable[1] + " - " + pid
                    row['State'] = state
                    row['CMD'] = get_command_line(pid)
                    if not u.islocalhost(ip):
                        latLon = getLatLon(ip)
                        row['LatLon'] = str(latLon)
                        row['Location'] = getAddress(latLon[0],latLon[1])
                        row['Domain'] = getDomain(ip) 
                        lat = str(latLon).replace("(","").replace(")","").split(',')[0]
                        lon = str(latLon).replace("(","").replace(")","").split(',')[1]
                        row['Link'] =  f"https://www.google.com/maps?q={lat},{lon}"
                        if allowRulesCreation == True:
                            fh.block_traffic(ip,port,protocol)
                    elif allowLocalRules:
                         if allowRulesCreation:
                            fh.block_traffic(ip,port,protocol)

                    df = df._append(row, ignore_index=True)
                    
        if update:
            dir = get_desktop_dir(filename)
            write_out_files(df, filename, dir)
            global isFirst 
            if isFirst == True:
                webbrowser.open(f"http://127.0.0.1:{u.port}/board")
                isFirst = False    
        print(f"{Colors.CYAN}sleep 2{Colors.RESET}")
        time.sleep(2)
        

def write_out_files(df, filename, dir):
    set_current_df(df)
    writer = pd.ExcelWriter(dir + filename)
    df.to_excel(writer, sheet_name='Sheet1', index=False)
    writer._save() 
    writer.close()
    html_file = dir + u.html_file
    html_buffer = StringIO()
    htmldf = df[["Time","Type","Conection","From","To","Task","Domain", "LatLon","Location", "Link", "State", "isBolcked",]].sort_values(by='Time', ascending=False)
    htmldf.to_html(html_buffer, index=False)
    html_content = html_buffer.getvalue()
    with open(html_file, 'w', encoding='utf-8') as file:
        file.write(html_content)

    u.update_html_file() # add autorelaod
    u.modify_process_to_Tasks_query() # modify process to tasks
    u.modify_google_maps_links() # modify google maps links
    u.modify_domain_to_DNSDumpster_link() # modify domains to serch in dns dumpster
    u.modyfy_ext_ip_to_dnschecker_link() # modify IP as link to dnschecker (serch if IP is in black list)
    u.limpiar_html()

def get_command_line(pid):
    try:
        # Obteniendo el proceso a partir del PID
        process = psutil.Process(int(pid))
        # Obteniendo la línea de comandos
        cmdline = process.cmdline()
        # Uniendo los argumentos en una sola cadena
        return ' '.join(cmdline)
    except psutil.NoSuchProcess:     return f"No se encontró un proceso con el PID {pid}"
    except Exception as e:           return f"Error: {str(e)}"

def get_desktop_dir(filename):
    dir = u.get_desktop_path() + u.OUTPUT_DIR
    if not os.path.exists(dir):
        os.mkdir(dir)
    if os.path.exists(dir + filename):
       pass # os.remove(dir + filename)
    return dir
	

def GetConnections(netstat_output):
    established_connections = [
            line.split() for line in netstat_output.splitlines() 
            if any(state in line for state in ["ESTABLISHED", "LISTENING", "SYN_SENT", "SYN_RECEIVED"])
        ]

    closed_connections = [
            line.split() for line in netstat_output.splitlines() 
            if any(state in line for state in ["CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSED"])
        ]
    
    return established_connections,closed_connections

def CloseConnetions(closed_connections):
    print(f'{Colors.CYAN}Closing  connections "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSED" {Colors.RESET}')
    time.sleep(1)
    
    for conn in closed_connections:
        state =conn[3]
        if state != "CLOSED":
            pid = conn[4]
            try:
                if pid != '0':
                    subprocess.run(["taskkill", "/PID", pid, "/F"], shell=True)
                    print(f'{Colors.GREEN}CLOSED {conn} {Colors.RESET}')
            except:
                print(f'{Colors.RED}error closing  {conn} {Colors.RESET}')

        
def  getDomain(ip):
    try:
       print(f"{Colors.BLUE}geting Domain for: {ip}{Colors.RESET}")
        # Get domain name from IP address
       return socket.gethostbyaddr(ip)[0]
    except socket.herror as e:
        print(f"{Colors.RED}Error getting domain name: {e}{Colors.RESET}")
    except socket.gaierror as e:
        print(f"{Colors.RED}Error getting location: {e}{Colors.RESET}")


def getLatLon(ip):  
    try:
        print(f"{Colors.BLUE}geting Lat and Lon for: {ip}{Colors.RESET}")
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        try:
            geolocation_data = response.json()  # Intentar decodificar el JSON
            lat = "0"
            lon = "0"
            try: 
                lat = geolocation_data["latitude"]
                lon = geolocation_data["longitude"]
            except: pass 
            return  (lat, lon)
        except requests.exceptions.JSONDecodeError:
            print(f'{Colors.RED}Error retrieving geolocation data: Response is not JSON or empty.{Colors.RESET}')
            return (0,0)
    except requests.exceptions.RequestException as e:
        print(f'{Colors.RED}Error retrieving geolocation data: {str(e)}{Colors.RESET}')
        return (0,0)


def getAddress(lat,lon):
    try: 
        print(f"{Colors.BLUE}geting location for: {lat} , {lon}{Colors.RESET}")
        url = 'https://nominatim.openstreetmap.org/reverse'
        params = {
            'lat': lat,
            'lon': lon,
            'format': 'json'
         }
        headers = {
            'User-Agent': 'mynetapp/1.0 (mynetapp@yahoo.com)'
            '''User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0'''
        }
       
        response = requests.get(url, params=params, headers=headers)
        if response.status_code != 200:
            raise Exception(f'Error retrieving reverse geocoding data: {response.json()}')
        reverse_geocoding_data = response.json()
        street_address = ""
        try: street_address = reverse_geocoding_data['address']['road']
        except KeyError: pass
        city =""
        try: city = reverse_geocoding_data['address']['city'] 
        except KeyError: pass
        country =""
        try: country = reverse_geocoding_data['address']['country']
        except KeyError: pass
        return (f"{street_address}, {city}, {country}")
    except KeyError as er:
        print(f'{Colors.RED}Error: {er}{Colors.RESET}')
        return ""

# querys over dataframe ------------------------------------------------------------------------------------------

# print(query_by_dest_ip(df, '0.0.0.0'))

def set_current_df(df):
    df_csv_file = u.get_desktop_path() + u.OUTPUT_DIR + 'current_df.csv' 
    df.to_csv(df_csv_file, index=False)

# run web server
def runServer():
    server_command = ["waitress-serve", "--port", str(u.port), "server:app"]
    env = os.environ.copy()
    env["PORT"] = str(u.port)
    flask_process = subprocess.Popen(server_command, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print("{colors.GREEN}- Opening Server on port {port}{colors.RESET}".format(colors=Colors, port=u.port))
    time.sleep(3)

    # Verifica la salida del proceso para depuración
    stdout, stderr = flask_process.communicate()
    print("STDOUT:", stdout.decode())
    print("STDERR:", stderr.decode())
    try:
         while True:
            time.sleep(1)  # Espera 1 segundo y vuelve a comprobar el evento de detención
    except KeyboardInterrupt:
        print("Stopping server...")
        flask_process.terminate()
        flask_process.wait()
        print("Server stopped.")       
    finally:
        flask_process.terminate()  # Enviar señal de terminación al proceso
        flask_process.wait()  # Esperar a que el proceso termine
        print("{colors.RED}- Server on port {port} has been stopped{colors.RESET}".format(colors=Colors, port=u.port))


    
# run as admin ----------------------------------------------------------------------------------------------------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    if not is_admin():
        print("Reiniciando el script con privilegios de administrador...")
        time.sleep(3)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        sys.exit()
    else:
        print("running as admin OK")



def minimize_console():
    # Obtén el identificador de la ventana de la consola
    hWnd = ctypes.windll.kernel32.GetConsoleWindow()
    if hWnd:
        # Usa la función ShowWindow para minimizar la ventana
        ctypes.windll.user32.ShowWindow(hWnd, 6)  # 6 = SW_MINIMIZE

def main():
 # Iniciar el ícono de la bandeja en un hilo separado
    tray_thread = threading.Thread(target=wh.create_Tray_menu)
    tray_thread.daemon = True
    tray_thread.start()

    # Iniciar el servidor en un hilo separado
    server_thread = threading.Thread(target=runServer)
    server_thread.daemon = True
    server_thread.start()

    fiewwall_thread = threading.Thread(target=fh.run_firewall)
    fiewwall_thread.deamon = True
    fiewwall_thread.start()

    # Iniciar la tarea de red en un hilo separado
    # net_task_thread = threading.Thread(target=netTask)
    # net_task_thread.daemon = True
    # net_task_thread.start()
    minimize_console()
    netTask()

    # Esperar hasta que el evento de detención se establezca
    # u.stop_event.wait()
    

if __name__ == '__main__':
    run_as_admin()
    main()
    # netTask()
