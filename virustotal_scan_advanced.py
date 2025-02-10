import os
import requests
import json
import time
import pandas as pd
import dash
from dash import dcc, html, Input, Output
import plotly.express as px
import plotly.graph_objects as go

# Configurações
API_KEY = 'ADICIONE AQUI SUA API KEY DO SEU CADASTRO NO VIRUS TOTAL'
API_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
MALWARE_DIR = '/home/kali/Downloads/theZoo-master/malware/malware_all/'
RESULTS_FILE = '/home/kali/Documents/scripts/report/virustotal_results.json'
PROCESSED_FILES_FILE = '/home/kali/Documents/scripts/report/processed_files.json'
POLLING_INTERVAL = 15  # Ajustado para o intervalo mínimo entre requisições
MAX_WAIT_TIME = 300    # Aumentado para 5 minutos para dar tempo ao processamento
API_DELAY = 15         # 15 segundos entre requisições (4/minuto)

# Variável de controle de rate limiting
last_request_time = 0

# Função para controlar o rate limiting


def make_api_request(url, files=None, params=None):
    global last_request_time
    current_time = time.time()

    # Calcula tempo restante para cumprir o rate limiting

    elapsed = current_time - last_request_time
    if elapsed < API_DELAY:
        wait_time = API_DELAY - elapsed
        print(f"Aguardando {wait_time:.1f} segundos para rate limiting...")
        time.sleep(wait_time)

    # Faz a requisição apropriada

    if files:
        response = requests.post(url, files=files, params=params)
    else:
        response = requests.get(url, params=params)

    # Atualiza o último timestamp

    last_request_time = time.time()
    return response

# Função para inferir o sistema operacional


def infer_os(file_name):
    if file_name.endswith(('.exe', '.dll')):
        return 'Windows'
    elif file_name.endswith(('.elf', '.sh', '.bin')):
        return 'Linux'
    elif file_name.endswith('.apk'):
        return 'Android'
    elif file_name.endswith(('.dmg', '.app')):
        return 'macOS'
    else:
        return 'Unknown'

# Função para enviar arquivo para o VirusTotal


def scan_file(file_path):
    with open(file_path, 'rb') as file:
        files = {'file': (os.path.basename(file_path), file)}
        params = {'apikey': API_KEY}
        response = make_api_request(API_URL, files=files, params=params)
        return response.json()

# Função para obter o relatório com polling ajustado


def get_report_with_polling(resource):
    start_time = time.time()
    while time.time() - start_time < MAX_WAIT_TIME:
        params = {'apikey': API_KEY, 'resource': resource}
        response = make_api_request(REPORT_URL, params=params)
        report = response.json()

        if report.get('response_code') == 1:
            return report

        print(f'Aguardando relatório para {resource}...')
        time.sleep(POLLING_INTERVAL)  # Sleep após verificação

    print(
        f'Relatório para {resource} não concluído em {MAX_WAIT_TIME} segundos.')
    return None

# Função para salvar resultados


def save_results(results):
    with open(RESULTS_FILE, 'w') as f:
        json.dump(results, f, indent=4)

# Função para carregar resultados


def load_results():
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, 'r') as f:
            return json.load(f)
    return []

# Função para carregar arquivos processados


def load_processed_files():
    if os.path.exists(PROCESSED_FILES_FILE):
        with open(PROCESSED_FILES_FILE, 'r') as f:
            return json.load(f)
    return []

# Função para salvar arquivos processados


def save_processed_files(processed_files):
    with open(PROCESSED_FILES_FILE, 'w') as f:
        json.dump(processed_files, f, indent=4)

# Processamento de resultados


def process_results(results):
    antivirus_stats = {}
    malware_info = []

    for result in results:
        if 'scans' in result:
            file_name = result.get('filename', 'unknown')
            os_type = result.get('os_type', 'Unknown')
            positives = sum(
                1 for scan in result['scans'].values() if scan['detected'])
            total = len(result['scans'])
            detection_rate = (positives / total) * 100 if total > 0 else 0

            malware_info.append({
                'Nome': file_name,
                'Sistema Operacional': os_type,
                'Detecções': positives,
                'Total de Antivírus': total,
                'Taxa de Detecção (%)': round(detection_rate, 2)
            })

            for antivirus, scan_result in result['scans'].items():
                if antivirus not in antivirus_stats:
                    antivirus_stats[antivirus] = {'detected': 0, 'total': 0}
                antivirus_stats[antivirus]['total'] += 1
                if scan_result['detected']:
                    antivirus_stats[antivirus]['detected'] += 1

    for antivirus, stats in antivirus_stats.items():
        stats['detection_rate'] = (stats['detected'] / stats['total']) * 100

    return antivirus_stats, malware_info


# Dashboard

app = dash.Dash(__name__)
app.layout = html.Div([
    html.H1("Dashboard de Análise de Malwares", style={'textAlign': 'center'}),
    dcc.Graph(id='top-antivirus'),
    dcc.Graph(id='os-distribution'),
    html.H3("Tabela de Malwares Analisados"),
    html.Div(id='malware-table')
])


@app.callback(
    [Output('top-antivirus', 'figure'),
     Output('os-distribution', 'figure'),
     Output('malware-table', 'children')],
    [Input('top-antivirus', 'id')]
)
def update_dashboard(_):
    results = load_results()
    antivirus_stats, malware_info = process_results(results)

    df_antivirus = pd.DataFrame.from_dict(
        antivirus_stats, orient='index').reset_index()
    df_antivirus.rename(columns={'index': 'Antivirus'}, inplace=True)
    df_malware = pd.DataFrame(malware_info)

    top_10 = df_antivirus.sort_values(
        by='detection_rate', ascending=False).head(10)
    fig_top_antivirus = px.bar(top_10, x='Antivirus', y='detection_rate',
                               title='Top 10 Antivírus que Mais Detectaram Malwares')

    os_distribution = df_malware['Sistema Operacional'].value_counts()
    fig_os_distribution = px.pie(os_distribution, values=os_distribution.values,
                                 names=os_distribution.index,
                                 title='Distribuição de Malwares por Sistema Operacional')

    table = dash.dash_table.DataTable(
        columns=[{"name": i, "id": i} for i in df_malware.columns],
        data=df_malware.to_dict('records'),
        style_table={'height': '300px', 'overflowY': 'auto'}
    )

    return fig_top_antivirus, fig_os_distribution, table


def main():
    results = load_results()
    processed_files = load_processed_files()

    for root, dirs, files in os.walk(MALWARE_DIR):
        for file in files:
            file_path = os.path.join(root, file)

            if file_path in processed_files:
                print(f'Arquivo {file_path} já foi processado. Pulando...')
                continue

            print(f'Enviando {file_path} para o VirusTotal...')

            try:
                scan_result = scan_file(file_path)
                resource = scan_result.get('resource')

                if resource:
                    print(f'Aguardando relatório para {file_path}...')
                    report = get_report_with_polling(resource)

                    if report:
                        report['filename'] = os.path.basename(file_path)
                        report['os_type'] = infer_os(
                            os.path.basename(file_path))

                        results.append(report)
                        save_results(results)
                        processed_files.append(file_path)
                        save_processed_files(processed_files)
                    else:
                        print(f'Relatório não disponível para {file_path}')
                else:
                    print(f'Erro ao enviar {file_path}')

            except Exception as e:
                print(f'Erro processando {file_path}: {str(e)}')

    print('Análise concluída. Iniciando dashboard...')
    app.run_server(debug=True)


if __name__ == '__main__':
    main()
