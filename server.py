import os
from flask import Flask, send_file, send_from_directory, request, jsonify, render_template
import utils as u
import logging
import json


app = Flask(__name__)

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger('werkzeug')

@app.route('/')
def home():
    return "Hello, Flask!"

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/board')
def serve_myfile():
    log.debug(f'Requested /board')
    folder = u.get_desktop_path() + u.OUTPUT_DIR
    external_static_folder = os.path.abspath(folder)
    log.debug(f'external_static_folder: {external_static_folder}')
    full_path = os.path.join(external_static_folder, u.html_file)
    log.debug(f'Trying to serve file from: {full_path}')

    if not os.path.exists(full_path):
        log.debug(f'File does not exist: {full_path}')
        return "File not found", 404
    else: return send_file(full_path)

@app.route('/task/')
def query_by_process_name_():
    process_name = request.args.get('process')
    if process_name:
        df_filtered = u.query_by_process_name(process_name)
        # df_to_json = df_filtered.to_dict(orient='records')
        # return jsonify(df_to_json)
        return render_template('task_template.html', data= df_filtered.to_dict(orient='records'), process_name=process_name)
    else:
        return jsonify({'error': 'No process name provided'})
        

# Asegurarse de que el archivo blocklist.json existe
if not os.path.exists(u.BLOCK_LIST_FILE):
    with open(u.BLOCK_LIST_FILE, 'w') as file:
        json.dump([], file)

# Asegurarse de que el archivo watchDogList.json existe
if not os.path.exists(u.WATCHDOG_LIST_FILE):
    with open(u.WATCHDOG_LIST_FILE, 'w') as file:
        json.dump([], file)


# Ruta para obtener el blocklist
@app.route('/get_blocklist', methods=['GET'])
def get_blocklist():
    with open(u.BLOCK_LIST_FILE, 'r') as file:
        blocklist = json.load(file)
    return jsonify({'blocklist': blocklist})


@app.route('/get_summary', methods=['GET'])
def get_sumary():
    # return jsonify(u.get_summary_df())
    return render_template('sumary_template.html', data= u.get_summary_df())


# Ruta para actualizar el blocklist
@app.route('/update_blocklist', methods=['POST'])
def update_blocklist():
    data = request.get_json()
    ip_to_block = data.get('ip')
    port_to_block = data.get('port')
    protocol = data.get('protocol')
    action = data.get('action')  # 'block' o 'unblock'

    with open(u.BLOCK_LIST_FILE, 'r') as file:
        blocklist = json.load(file)

    blocklist = update_or_remove_entry(blocklist, ip_to_block, port_to_block, protocol, action)
    with open(u.BLOCK_LIST_FILE, 'w') as file:
        json.dump(blocklist, file)

    return jsonify({'status': 'success'})





def update_or_remove_entry(blocklist, ip_to_block, port_to_block, protocol, action):
    # Crear un nuevo registro con la IP, puerto y protocolo proporcionados
    entry_to_update = {'ip': ip_to_block, 'port': port_to_block, 'protocol': protocol, 'action': action}

    # Buscar el índice del registro que coincida con IP, puerto y protocolo
    for index, entry in enumerate(blocklist):
        if entry['ip'] == ip_to_block and entry['port'] == port_to_block and entry['protocol'] == protocol:
            # Actualizar el action si ya existe
            blocklist[index] = entry_to_update
            return blocklist
    # Si no se encontró un registro que coincida, agregar el nuevo registro
    blocklist.append(entry_to_update)
    return blocklist



@app.route('/update_watchdog', methods=['POST'])
def update_watchdog():
    data = request.get_json()
    action = data.get('action')  # 'block' o 'unblock'
    porc_to_block = data.get('proc')

    with open(u.WATCHDOG_LIST_FILE, 'r') as file:
        watchdoglist = json.load(file)

    watchdoglist = update_or_remove_watchdog_entry(watchdoglist, action, porc_to_block)
    with open(u.WATCHDOG_LIST_FILE, 'w') as file:
        json.dump(watchdoglist, file)

    return jsonify({'status': 'success'})


def update_or_remove_watchdog_entry(watchdoglist,action, porc_to_block):
    # Crear un nuevo registro con la IP, puerto y protocolo proporcionados
    entry_to_update = {'action': action, 'proc': porc_to_block}

    # Buscar el índice del registro que coincida con IP, puerto y protocolo
    for index, entry in enumerate(watchdoglist):
        if entry['proc'] == porc_to_block:
            # Actualizar el action si ya existe
            watchdoglist[index] = entry_to_update
            return watchdoglist
    # Si no se encontró un registro que coincida, agregar el nuevo registro
    watchdoglist.append(entry_to_update)
    return watchdoglist



@app.route('/get_analytics', methods=['GET'])
def analisis_conexiones():
    try:
        df = u.get_current_df()
        return jsonify(json.loads( u.get_coincidences(df)))  # Convertir de vuelta a dict para jsonify
    except Exception as e:
        print(f"Error en analisis_conexiones: {e}")
        return jsonify({"error": "Error en el análisis de conexiones"}), 500
    

if __name__ == '__main__':
    port = int(os.environ.get('PORT', u.port))
    log.debug(f'Starting Flask server on port {port}')
    app.run(debug=True, port=port)





