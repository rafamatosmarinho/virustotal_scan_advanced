# Análise de Malwares com VirusTotal e Dashboard Interativo

## Aviso Importante

Antes de tudo, utilize uma máquina virtual para executar esses scripts!
Rodar arquivos maliciosos em um ambiente de produção ou na sua máquina principal pode comprometer seu sistema e seus dados.

1. Download e Extração dos Malwares

Baixe o repositório theZoo contendo amostras de malwares:

```bash
git clone https://github.com/ytisf/theZoo.git
```

Extraia o conteúdo para o diretório /home/kali/Downloads/:

```bash
unzip theZoo-master.zip -d /home/kali/Downloads/
```

2. Extração dos Executáveis

Baixe o script find_exec.py do repositório:

```bash
wget https://raw.githubusercontent.com/rafamatosmarinho/malware-organizer/main/find_exec.py
```

## Execute o script para extrair os executáveis:

```bash
python find_exec.py /home/kali/Downloads/theZoo-master/
```

3. Execução do Script de Análise

Configure sua API Key do VirusTotal no script.

Execute o script de análise:

```bash
python seu_script.py
```

4. Dashboard Interativo

O script gera um dashboard interativo para visualizar os resultados da análise dos malwares.

Acesse o dashboard pelo navegador:

http://localhost:8050
