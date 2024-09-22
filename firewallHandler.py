import ctypes
import os
import subprocess
import sys
import utils as u
import json
import time

RULES_FILE = 'firewall_rules.txt'


class Colors:
    RESET = "\033[0m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

# main live firewall rules create and delete --------------------------------------------------

def monitor_lists(interval=1):
    if not os.path.exists(u.BLOCK_LIST_FILE):
        with open(u.BLOCK_LIST_FILE, 'w') as file:
            json.dump([], file)
    if not os.path.exists(u.WATCHDOG_LIST_FILE):
        with open(u.WATCHDOG_LIST_FILE, 'w') as file:
            json.dump([], file) 
    while True:
        apply_blocklist()
        apply_watchdog()
        print(f'sleelp {interval}')
        time.sleep(interval)


def apply_watchdog():
    with open(u.WATCHDOG_LIST_FILE, 'r') as file:
        watchdog_list = json.load(file)
        df = u.get_current_df()
        for entry in watchdog_list:
            proc = entry['proc']
            action = entry['action']
            if action == 'block':
                df_resultante = filtrar_proceso(df, proc)
                estados_validos =  ["ESTABLISHED", "LISTENING", "SYN_SENT", "SYN_RECEIVED"]
                df_resultante = df_resultante[df_resultante['State'].isin(estados_validos)]
                if len(df_resultante) > 0:
                    print(f'validando coneciones de aplicacion: {proc}')
                    for index, row in df_resultante.iterrows():
                        pid = row['PID']
                        ip = row['To_IP']
                        print(f'Cerrando aplicaciones: {proc}, {pid}, {ip}')

                        if not u.islocalhost(ip):
                            try:
                                if pid != '0' and pid is not None:
                                    subprocess.run(["taskkill", "/PID", pid, "/F"], shell=True)
                                    print('cerrado')
                            except Exception as e:
                                print(f'Error al cerrar aplicaciones: {proc}, {pid}, {ip}: {e}')
                                pass
                        else:
                            print(f'{pid} {ip} es localhost')
            
                
def close_connections(proc):
    try:
        df = u.get_current_df()
        pid = df['Task'].str.split('-')[1].values
        if pid != '0':
            subprocess.run(["taskkill", "/PID", pid, "/F"], shell=True)
        print(f'Cerrando aplicaciones: {proc}')
    except:
        print(f'Error al cerrar aplicaciones: {proc}')

def apply_blocklist():
    with open(u.BLOCK_LIST_FILE, 'r') as file:
        blocklist = json.load(file)

    for entry in blocklist:
        ip = entry['ip']
        port =  entry['port']
        protocol = entry['protocol']
        action = entry['action']
        rule_name = generate_rule_name(ip=ip, port=port)
        if action == 'block':
            block_traffic(ip=ip, port=port, protocol=protocol)
        elif action == 'unblock':
            remove_simple_rule(rule_name=rule_name, auto=True)



def block_traffic(ip=None, port=None, protocol='TCP'):
    '''
    Ejemplos de uso:
    Bloquear una IP específica
    block_traffic(ip="192.168.1.100", protocol="TCP")
    Bloquear un puerto específico
    block_traffic(port=1234, protocol="UDP")
    '''
    
    incommand = ""
    outcommand = ""
    if ip and port:
        # Bloquear IP y puerto
        incommand = f"netsh advfirewall firewall add rule name=\"Block IP {ip} and port {port} in\" protocol={protocol} dir=in remoteip={ip}  action=block"
    elif ip:
        # Bloquear solo IP
        incommand = f"netsh advfirewall firewall add rule name=\"Block IP {ip} in\" protocol={protocol} dir=in remoteip={ip} action=block"
    elif port:
        # Bloquear solo puerto
        incommand = f"netsh advfirewall firewall add rule name=\"Block port {port} in\" protocol={protocol} dir=in localport={port} action=block"
    else:
        raise ValueError(" must provide either an IP, a port, or both to block.")
    # Ejecutar el comando
    rules = read_rules_in_file()
    if not incommand in rules:
        add_simple_rule(incommand, auto=True)
    # else:  print(f"{Colors.GREEN}Regla ya existe: {command} {Colors.RESET}")
    if ip and port:
        # Bloquear IP y puerto
        outcommand = f"netsh advfirewall firewall add rule name=\"Block IP {ip} and port {port} out\" protocol={protocol} dir=out remoteip={ip}  action=block"
    elif ip:
        # Bloquear solo IP
        outcommand = f"netsh advfirewall firewall add rule name=\"Block IP {ip} out\" protocol={protocol} dir=out remoteip={ip} action=block"
    elif port:
        # Bloquear solo puerto
        outcommand = f"netsh advfirewall firewall add rule name=\"Block port {port} out\" protocol={protocol} dir=out localport={port} action=block"
    else:
        raise ValueError(" must provide either an IP, a port, or both to block.")
    # Ejecutar el comando
    rules = read_rules_in_file()
    if not outcommand in rules:
        add_simple_rule(outcommand, auto=True)
    # else:  print(f"{Colors.GREEN}Regla ya existe: {command} {Colors.RESET}")


def add_simple_rule(command, auto=False):
    response = 'n'
    if auto == False:
        response = get_user_confirmation(f"Apply new rule to firewall?:\n {command}")
    if response == 'Y' or auto == True:
        try:
            subprocess.run(command, shell=True, check=True) # uncomment to apply the rule in firewall <------------------
            add_rule_to_file(command)
            u.showNotification(command)
            print(f"{Colors.GREEN}Regla de firewall aplicada: {command} {Colors.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error al aplicar la regla de firewall: {e}{Colors.RESET}")
    elif response == 'C':
        print("Proceso cancelado por el usuario.")
        exit()


def remove_simple_rule(rule=None, rule_name=None, auto=False):
    rules = read_rules_in_file()
    response = 'n'
    ruleExist = False

    if rule != None:
        if rule in rules: ruleExist = True
        name_part = rule.split('name=')[1].split(' ')[0].strip('"')
    elif rule_name != None:
        name_part = rule_name
        ruleExist = any(rule_name in rule for rule in rules)
        rule = next((rule for rule in rules if rule_name in rule), None)
    
    command =  f"netsh advfirewall firewall delete rule name=\"{name_part}\""
    if auto == False: 
        response = get_user_confirmation(f"¿Desea eliminar la regla: {name_part}?")
    if response == 'Y' or auto == True:
        try:
            if ruleExist:
                subprocess.run(command, shell=True, check=True) # uncomment to enable rule deletion
                print(f"{Colors.GREEN}Regla de firewall eliminada: {command}{Colors.RESET}")
                remove_rule_to_file(rule.strip())
            # else: print(f"{Colors.MAGENTA}NO existe regla para eliminar: {command}{Colors.RESET}")
        except subprocess.CalledProcessError as e:
            print(f"{Colors.RED}Error al eliminar la regla de firewall: {e}{Colors.RESET}")
    elif response == 'C':
        print("Proceso cancelado por el usuario.")
        exit()


# extra firewall functionalities ---------------------------------------------------------

def UN_block_ALL_traffic():
    if not os.path.exists(RULES_FILE):
        print("El archivo de reglas no existe.")
        return
    with open(RULES_FILE, 'r') as file:
        rules = file.readlines()
    for rule in rules:
        remove_simple_rule(rule=rule, auto=True)


def list_firewall_rules(name_filter=None):
    # Ejecutar el comando para obtener todas las reglas
    command = "netsh advfirewall firewall show rule name=all"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    # Filtrar las líneas que contienen el nombre de la regla
    rules = result.stdout.splitlines()
    filtered_rules = [line for line in rules if name_filter in line]
    
    # Mostrar las reglas filtradas
    for rule in filtered_rules:
        print(rule)


# firewall log file for rules methods ----------------------------------------------------------------


def read_rules_in_file():
    with open(RULES_FILE, 'r') as file:
        rules = [line.strip() for line in file.readlines()]
        return rules


def add_rule_to_file(rule):
    with open(RULES_FILE, 'a') as file:
        file.write(rule + '\n')


def remove_rule_to_file(rule):
    rules = None
    with open(RULES_FILE, 'r') as file:
        rules = file.readlines()
    try: rules.remove(rule + '\n')
    except ValueError:
        print(f"La regla '{rule}' no se encontró en el archivo.")
    with open(RULES_FILE, 'w') as file:
        file.writelines(rules)


# aux methods -------------------------------------------------------------------------------------------------


def get_user_confirmation(prompt):
    while True:
        response = input(prompt + "\n  (Y/N/C(cancel all)): ").strip().upper()
        if response in ['Y', 'N', 'C']:
            return response
        else:
            print("Respuesta inválida. Por favor, ingrese 'Y' para sí, 'N' para no, o 'C' para cancelar todo.")


def generate_rule_name(ip=None, port=None):
    if ip and port:
        return f"Block IP {ip} and port {port}"
    elif ip:
        return f"Block IP {ip}"
    elif port:
        return f"Block port {port}"
    else:
        return None



import pandas as pd

def filtrar_proceso(df, proceso):
    df_filtrado = df[df['Task'].str.contains(proceso, na=False)]
    df_filtrado = df_filtrado.copy() 
    df_filtrado[['Proceso', 'PID']] = df_filtrado['Task'].str.split(' - ', expand=True)

    df_filtrado[['To_IP' ,'To_Port']] = df_filtrado['To'].str.extract(r'^(.*):([^:]*)$')

    df_resultante = df_filtrado[['Proceso', 'PID', 'To_IP', 'To_Port', 'State']]

    df_resultante = df_resultante.drop_duplicates()
    return df_resultante





# FIREWALL END -----------------------------------------------------------------------------------------------------

# run live firewall methos -----------------------------------------------------------------------------------------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    if not is_admin():
        print("Reiniciando el script con privilegios de administrador...")
        time.sleep(5)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, ' '.join(sys.argv), None, 1)
        sys.exit()
    else:
        print("running as admin OK")


def run_firewall():
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'w') as file:
            pass 
    monitor_lists()


if __name__ == '__main__':
    # run_as_admin()
    run_firewall()
