# -*- coding: utf-8 -*-

"""
================================================================================
                            FIX-STEAMTOOLS
================================================================================
 
 Projetada para neutralizar os componentes maliciosos
 da 'hid.dll' (modificada pela SteamTools) sem quebrar sua funcionalidade
 principal (carregar manifestos de jogos).

 ESTRATÉGIA DE NEUTRALIZAÇÃO EM DUAS CAMADAS:
 
   1. CAMADA 1 (CIRURGIA NA DLL):
      Desativa o backdoor passivo (conexões *entrantes*).
      Localizamos as funções 'accept', 'listen', e 'bind' na Tabela de
      Importação da DLL e sobrescrevemos seus endereços com zeros (Patch IAT).
      Isso impede o malware de "abrir uma porta" e "ouvir" por conexões
      de um invasor.

   2. CAMADA 2 (BLOQUEIO DE REDE):
      Desativa a exfiltração de dados (conexões *saindo*).
      Identificamos os domínios de Comando e Controle (C2) com os quais
      o malware tenta se comunicar e os bloqueamos no arquivo 'hosts'
      do Windows.
      
 MELHORIAS v0.1.0:
  - Adicionada limpeza de 'hosts': Remove blocos duplicados/antigos antes
    de adicionar o novo, impedindo que o arquivo 'hosts' fique poluído.
  - Adicionado Patch Atômico: Evita corrupção da DLL se o script falhar.
  - Adicionada Análise de Strings: Detecta URLs maliciosas e comandos.
  - Adicionada Detecção de Múltiplos Nomes: Procura por 'hid.dll', etc.
  - Adicionada Verificação Real de Permissão: Checa a permissão de escrita.
================================================================================
"""

# === [ AVISO LEGAL E DE ISENÇÃO DE RESPONSABILIDADE ] ===
#
# 1. PROPÓSITO: Este script é fornecido estritamente para fins
#    educacionais e de segurança defensiva.
#
# 2. "COMO ESTÁ": Este software é fornecido "COMO ESTÁ" (AS IS),
#    sem qualquer garantia, expressa ou implícita.
#
# 3. SEM RESPONSABILIDADE: Em nenhuma circunstância o autor ou
#    contribuidores serão responsáveis por quaisquer danos, perdas
#    (incluindo, mas não limitado a, perda de dados, corrupção de
#    sistema, ou banimentos de conta) decorrentes do uso ou da
#    incapacidade de usar este software.
#
# 4. USE POR SUA CONTA E RISCO: Você entende e concorda que
#    está usando este script por sua inteira conta e risco.
#
# 5. AVISO IMPORTANTE SOBRE A DLL: Este script NÃO remove
#    a 'hid.dll' modificada pelo SteamTools. Ele apenas *tenta*
#    neutralizar seus componentes maliciosos conhecidos (patching).
#    A DLL subjacente ainda é de uma fonte não confiável e
#    pode conter outros vetores de ameaça desconhecidos.
#
# 6. SEM AFILIAÇÃO: Esta ferramenta não é afiliada, endossada ou
#    patrocinada pela Valve Corporation (Steam) ou pelos
#    criadores do SteamTools.
#
# AO EXECUTAR ESTE SCRIPT, VOCÊ RECONHECE QUE LEU E
# CONCORDA COM ESTES TERMOS.
# ============================================================================


import os
import sys
import subprocess
import ctypes
import shutil
from datetime import datetime
import time
import platform # Para checar a arquitetura do OS
import hashlib  # Importado para hashes
import winreg   # Para encontrar a Steam
import re       # Importado para Análise de Strings

# --- [1. VERIFICAÇÃO DE DEPENDÊNCIAS (Terceiros)] ---
try:
    import pefile
    import psutil
except ImportError:
    print("[-] Dependências necessárias (pefile, psutil) não encontradas.")
    print("[*] Este script tentará instalá-las agora usando 'pip'.")
    try:
        # Usa o executável do Python atual para chamar o pip
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile", "psutil"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("\n[+] Dependências instaladas com sucesso.")
        # Tenta importar novamente após a instalação
        import pefile
        import psutil
    except Exception as e:
        print(f"\n[X] FALHA CRÍTICA: Não foi possível instalar as dependências: {e}")
        print("    Verifique sua conexão com a internet ou instale manually no seu terminal:")
        print("    pip install pefile psutil")
        input("Pressione Enter para sair.")
        sys.exit(1)


# --- [2. CONFIGURAÇÃO GLOBAL DE ALVOS] ---

# Caminho do arquivo hosts do Windows (este é padrão)
HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
# Nome do processo da Steam a ser verificado
STEAM_PROCESS_NAME = "steam.exe"

# Nomes de DLL candidatas
DLL_CANDIDATES = ["hid.dll", "hid64.dll", "hid32.dll"]

# Alvos da Camada 1 (Cirurgia na DLL)
TARGETS_TO_PATCH = [
    (b"WS2_32.dll", b"accept"),  # Impede de *aceitar* conexões
    (b"WS2_32.dll", b"listen"),  # Impede de *ouvir* por conexões
    (b"WS2_32.dll", b"bind")     # Impede de *se ligar* a uma porta
]

# Alvos da Camada 2 (Bloqueio de Rede)
DOMAINS_TO_BLOCK = [
    "update.wudrm.com",
    "stools.oss-cn-shanghai.aliyuncs.com"
]
# Marcador para garantir que não duplicamos as entradas no hosts
HOSTS_BLOCK_MARKER = "# [FIX-STEAMTOOLS] Bloco de domínios maliciosos"

# MARCADORES ANTIGOS PARA LIMPEZA (v0.1.0)
OLD_HOSTS_MARKERS = [
    "# [NEUTRALIZE SCRIPT]"
]


# Lista para análise de funções suspeitas (para o relatório)
SUSPICIOUS_IMPORTS = {
    b"ws2_32.dll": "Alto Risco. Contém funções de rede (conectar, enviar, receber, ouvir).",
    b"crypt32.dll": "Médio Risco. Usada para criptografia e certificados. Suspeito para uma HID.dll.",
    b"advapi32.dll": "Médio Risco. Funções 'Crypt' (como CryptGenRandom) são usadas para criptografia."
}
SUSPICIOUS_ADVAPI_FUNCS_PREFIX = b"Crypt" # Funções como CryptAcquireContext, CryptCreateHash, etc.

# Lista para Análise de Strings (para o relatório)
SUSPICIOUS_STRING_PATTERNS = {
    # Domínios C2 Conhecidos
    re.compile(b"update.wudrm.com"): "Domínio de C2 Conhecido",
    re.compile(b"stools.oss-cn-shanghai.aliyuncs.com"): "Domínio de C2 Conhecido",
    # Genéricos
    re.compile(b"powershell", re.IGNORECASE): "Possível executor de script (PowerShell)",
    re.compile(b"cmd.exe", re.IGNORECASE): "Possível executor de comando (CMD)",
    re.compile(b"http://"): "Comunicação de rede não criptografada (HTTP)"
}


# --- [3. FUNÇÕES PRINCIPAIS] ---

def print_disclaimer_and_get_consent():
    """
    Exibe o disclaimer e exige que o usuário digite 'EU CONCORDO' para prosseguir.
    """
    print("="*80)
    print("         AVISO LEGAL E DE ISENÇÃO DE RESPONSABILIDADE")
    print("="*80)
    print("1. PROPÓSITO: Este script é fornecido estritamente para fins")
    print("   educacionais e de segurança defensiva.")
    print("\n2. SEM RESPONSABILIDADE: O autor não se responsabiliza por")
    print("   quaisquer danos, perdas ou banimentos de conta decorrentes")
    print("   do uso deste software ou de outros ligados a esse script.")
    print("\n3. USE POR SUA CONTA E RISCO: Você entende que está usando este")
    print("   script por sua inteira conta e risco.")
    print("\n4. AVISO SOBRE A DLL: Este script NÃO remove a DLL modificada,")
    print("   ele apenas TENTA neutralizar seus componentes maliciosos.")
    print("   A DLL subjacente AINDA É DE UMA FONTE NÃO CONFIÁVEL.")
    print("\nCódigo Fonte: https://github.com/lucaswotta/fix-steamtools")
    print("="*80)
    
    try:
        print("Para continuar, você deve ler e aceitar os termos acima.")
        consent = input("Digite 'EU CONCORDO' (em maiúsculas) e pressione Enter: ")
        
        if consent.strip() == "EU CONCORDO":
            print("[+] Consentimento aceito. O script continuará.")
            time.sleep(1)
        else:
            print("[X] Consentimento não fornecido. Saindo.")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n[X] Operação cancelada pelo usuário. Saindo.")
        sys.exit(0)

def check_for_admin_rights():
    """
    Verifica se o script tem privilégios de Administrador.
    Necessário para modificar 'Program Files (x86)' e 'System32'.
    """
    print("[*] Verificando privilégios de Administrador...")
    is_admin = False
    try:
        is_admin = (os.getuid() == 0)
    except AttributeError:
        # Método para Windows
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
    if not is_admin:
        print("\n[X] FALHA: Privilégios de Administrador necessários.")
        print("    Por favor, execute este script como Administrador.")
        input("\nPressione Enter para sair.")
        sys.exit(1)
    
    print("[+] Privilégios de Administrador confirmados.")
    
    # Verificação de Permissão Real
    print("[*] Verificando permissão de escrita no arquivo 'hosts'...")
    if not os.access(HOSTS_FILE_PATH, os.W_OK):
        print("\n[X] FALHA DE PERMISSÃO REAL: O script não pode escrever em")
        print(f"    '{HOSTS_FILE_PATH}'.")
        print("    Isso geralmente é causado por um Antivírus (Proteção de Módulo,")
        print("    Proteção de Hosts, etc.). Desative-o temporariamente e tente de novo.")
        input("\nPressione Enter para sair.")
        sys.exit(1)
        
    print("[+] Permissão de escrita no 'hosts' confirmada.")


def handle_steam_process():
    """
    Verifica se a Steam está em execução e pede ao usuário para fechá-la.
    Oferece fechar o processo automaticamente.
    """
    print("[*] Verificando se a Steam está em execução...")
    steam_found = False
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == STEAM_PROCESS_NAME:
            steam_found = True
            try:
                p = proc
                print(f"[!] ALERTA: A Steam ('{STEAM_PROCESS_NAME}') está em execução (PID: {p.pid}).")
                print("    A DLL não pode ser modificada enquanto a Steam estiver aberta.")
                
                # Pedir consentimento para fechar
                while True:
                    choice = input("    Deseja que este script feche a Steam para você? (s/n): ").lower()
                    if choice == 's':
                        print(f"[*] Encerrando o processo {STEAM_PROCESS_NAME}...")
                        p.kill()
                        p.wait() # Espera o processo ser totalmente encerrado
                        print("[+] Processo da Steam encerrado.")
                        time.sleep(2) # Pequena pausa para o sistema liberar o arquivo
                        return True
                    elif choice == 'n':
                        print("[X] Por favor, feche a Steam manually e execute o script novamente.")
                        input("Pressione Enter para sair.")
                        sys.exit(0)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[X] Erro ao tentar acessar o processo da Steam: {e}")
                print("    Por favor, feche a Steam manualmente e execute o script novamente.")
                input("Pressione Enter para sair.")
                sys.exit(1)

    if not steam_found:
        print("[+] Processo da Steam não encontrado. Bom para prosseguir.")
        return True

def find_steam_and_dll():
    """
    Encontra o caminho de instalação da Steam e a DLL maliciosa.
    Retorna o caminho (string) da DLL ou None se não for encontrado.
    """
    print("[*] Localizando a pasta de instalação da Steam via Registro do Windows...")
    
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam"),
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam") 
    ]
    
    steam_path = None
    for hkey, path in registry_paths:
        try:
            with winreg.OpenKey(hkey, path) as key:
                install_path, _ = winreg.QueryValueEx(key, "InstallPath")
                if install_path and os.path.isdir(install_path):
                    print(f"[+] Steam encontrada em: {install_path}")
                    steam_path = install_path
                    break
        except FileNotFoundError:
            continue
        except Exception as e:
            print(f"[!] Aviso: Ocorreu um erro ao ler o registro ({path}): {e}")
            
    if not steam_path:
        print("\n[X] FALHA: Não foi possível localizar a pasta de instalação da Steam.")
        print("    A Steam está instalada neste computador?")
        return None
        
    # Agora procura a DLL
    print("[*] Procurando por DLLs alvo do SteamTools...")
    for dll_name in DLL_CANDIDATES:
        dll_path = os.path.join(steam_path, dll_name)
        if os.path.exists(dll_path):
            print(f"[+] DLL alvo encontrada: {dll_path}")
            return dll_path
            
    print(f"\n[X] FALHA: A Steam foi encontrada, mas nenhuma das DLLs alvo")
    print(f"    ({', '.join(DLL_CANDIDATES)}) foi localizada na pasta.")
    print("    O SteamTools parece não estar instalado.")
    return None


def get_file_md5(filepath):
    """Calcula o hash MD5 de um arquivo de forma segura."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"[!] Aviso: Não foi possível calcular o MD5: {e}")
        return "N/A"

def get_file_sha256(filepath):
    """Calcula o hash SHA256 de um arquivo de forma segura."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"[!] Aviso: Não foi possível calcular o SHA256: {e}")
        return "N/A"

def scan_strings(filepath):
    """
    Lê o arquivo e procura por strings suspeitas.
    Retorna uma lista de strings encontradas.
    """
    print("[*] Iniciando Análise de Strings (Nível 2)...")
    found_strings = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        for pattern, description in SUSPICIOUS_STRING_PATTERNS.items():
            if pattern.search(data):
                # Tenta decodificar a string encontrada para ser legível
                match_str = pattern.search(data).group(0).decode('ascii', errors='ignore')
                report = f"'{match_str}' (Justificativa: {description})"
                if report not in found_strings:
                    found_strings.append(report)
                    
    except Exception as e:
        print(f"[!] Aviso: Falha na Análise de Strings: {e}")
        
    return found_strings

def analyze_and_report(dll_path):
    """
    Analisa a DLL em busca de importações perigosas e salva um relatório.
    Retorna a string do relatório para exibição no console.
    """
    print(f"[*] Analisando a DLL alvo: {dll_path}")
    
    if not os.path.exists(dll_path):
        print("[X] FALHA: A 'hid.dll' não foi encontrada no caminho da Steam.")
        return None

    try:
        pe = pefile.PE(dll_path)
        
        signature_status = "NÃO ASSINADA (SUSPEITO)"
        if hasattr(pe, 'OPTIONAL_HEADER') and \
           hasattr(pe.OPTIONAL_HEADER, 'DATA_DIRECTORY') and \
           len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']:
            
            security_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            if security_entry.Size > 0:
                signature_status = "ASSINADA DIGITALMENTE (Inesperado!)"
                print("[!] ALERTA: Esta DLL parece ser assinada digitalmente.")
                print("    Isso é INESPERADO para a DLL do SteamTools, mas comum em malware")
                print("    que injeta código em DLLs legítimas. Prosseguindo com a análise.")
            
        report_lines = [
            f"Relatório de Análise para: {dll_path}",
            f"Data da Análise: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}",
            f"Tamanho: {os.path.getsize(dll_path)} bytes",
            f"MD5: {get_file_md5(dll_path)}",
            f"SHA256: {get_file_sha256(dll_path)}",
            f"Assinatura Digital: {signature_status}",
        ]
        
        # --- Análise de Importações (Nível 1) ---
        report_lines.extend([
            "\n=======================================================",
            " NÍVEL 1: FUNÇÕES POTENCIALMENTE PERIGOSAS (IMPORTAÇÕES)",
            "=======================================================\n"
        ])
        
        found_suspects = []

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name_lower = entry.dll.lower()
                
                if dll_name_lower in SUSPICIOUS_IMPORTS:
                    report_lines.append(f"[!] DLL Importada: {entry.dll.decode()} (Justificativa: {SUSPICIOUS_IMPORTS[dll_name_lower]})")
                    found_suspects.append(entry.dll.decode())
                    for imp in entry.imports:
                        if imp.name:
                            report_lines.append(f"    -> Função: {imp.name.decode()}")
                
                elif dll_name_lower == b"advapi32.dll":
                    crypto_funcs_found = []
                    for imp in entry.imports:
                        if imp.name and imp.name.lower().startswith(SUSPICIOUS_ADVAPI_FUNCS_PREFIX.lower()):
                            crypto_funcs_found.append(imp.name.decode())
                    
                    if crypto_funcs_found:
                        report_lines.append(f"[!] DLL Importada: {entry.dll.decode()} (Justificativa: {SUSPICIOUS_IMPORTS[b'advapi32.dll']})")
                        found_suspects.append(entry.dll.decode())
                        for func_name in crypto_funcs_found:
                             report_lines.append(f"    -> Função: {func_name}")
        else:
            report_lines.append("[X] A DLL não possui uma Tabela de Importação. Isso é altamente incomum.")
        
        if not found_suspects:
             report_lines.append("\n[+] Nenhuma das DLLs de alto risco (WS2_32, CRYPT32) foi encontrada.")

        pe.close()
        
        # --- Análise de Strings (Nível 2) ---
        report_lines.extend([
            "\n=======================================================",
            " NÍVEL 2: STRINGS SUSPEITAS ENCONTRADAS NO ARQUIVO",
            "=======================================================\n"
        ])
        
        found_strings = scan_strings(dll_path)
        if found_strings:
            for s in found_strings:
                report_lines.append(f"[!] String Encontrada: {s}")
        else:
            report_lines.append("[+] Nenhuma string suspeita (URLs de C2, comandos) foi encontrada.")
             
        # --- Salvar o Relatório em Arquivo ---
        report_filename = f"fix-steamtools_analise_{datetime.now().strftime('%d%m%Y')}.txt"
        report_path = os.path.join(os.path.dirname(sys.argv[0]), report_filename)
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(report_lines))
            saved_msg = f"Relatório de análise salvo em: {report_path}"
            print(f"[+] {saved_msg}")
            report_lines.insert(0, f"{saved_msg}\n")
        except PermissionError:
            print(f"[X] FALHA DE PERMISSÃO: Não foi possível salvar o relatório em {report_path}")
        except Exception as e:
            print(f"[X] FALHA: Não foi possível salvar o relatório: {e}")

        
        # Retorna as linhas para impressão no console
        return "\n".join(report_lines)

    except pefile.PEFormatError:
        print(f"\n[X] FALHA: O arquivo '{dll_path}' está corrompido ou não é uma DLL válida.")
        return None
    except Exception as e:
        print(f"\n[X] FALHA: Erro desconhecido ao analisar a DLL: {e}")
        return None

def get_user_consent_to_patch(analysis_report_str):
    """
    Exibe o plano de ação e o relatório de análise, e pede consentimento.
    """
    print("\n" + "="*80)
    print("                  RELATÓRIO DE AMEAÇA ENCONTRADA")
    print("="*80)
    print(analysis_report_str)
    print("\n" + "="*80)
    print("                      PLANO DE NEUTRALIZAÇÃO")
    print("="*80)
    print("Baseado na análise, esta ferramenta executará as seguintes operações de segurança:")

    print("\n[AÇÃO 1: BACKUP DE SEGURANÇA]")
    print("  - ANTES de qualquer alteração, uma cópia exata da DLL será")
    print("    salva como 'hid.dll.bak'. Seu arquivo original ficará seguro.")

    print("\n[AÇÃO 2: NEUTRALIZAÇÃO DO BACKDOOR (CAMADA 1)]")
    print("  - Objetivo: Desativar a capacidade da DLL de receber conexões de invasores.")
    print("  - Método: O script aplicará um 'patch' na Tabela de Importação (IAT)")
    print("    sobrescrevendo as seguintes funções com bytes nulos (0x00):")
    print(f"    Funções Alvo: {', '.join([f.decode() for d, f in TARGETS_TO_PATCH])}")

    print("\n[AÇÃO 3: BLOQUEIO DE REDE (CAMADA 2)]")
    print("  - Objetivo: Impedir que o malware 'ligue para casa' para enviar seus dados.")
    print("  - Método: O script modificará seu arquivo 'hosts' do Windows para")
    print("    redirecionar os domínios maliciosos para um 'buraco negro' (0.0.0.0).")
    print("  - Domínios Bloqueados:")
    for domain in DOMAINS_TO_BLOCK:
        print(f"    - {domain}")

    print("\n[AÇÃO 4: VERIFICAÇÃO E ROLLBACK AUTOMÁTICO]")
    print("  - Após a operação, o script fará uma auditoria completa para")
    print("    garantir que ambas as camadas de defesa estão ativas.")
    print("  - IMPORTANTE: Se a verificação da DLL falhar, o script irá")
    print("    automaticamente restaurar o backup para não corromper sua Steam.")
        
    print("\n" + "="*80)
    
    try:
        input("Pressione [ENTER] para INICIAR a neutralização ou [CTRL+C] para cancelar...")
        print("Iniciando operação...")
    except KeyboardInterrupt:
        print("\n\n[X] Operação cancelada pelo usuário.")
        sys.exit(0)

def apply_layer_1_patch(dll_path):
    """
    Aplica o IAT Patching (Camada 1) usando um método de patch atômico.
    Retorna True se bem-sucedido, False se falhar.
    """
    print("\n--- [INICIANDO CAMADA 1: CIRURGIA NA DLL] ---")
    
    backup_path = dll_path + ".bak"
    temp_path = dll_path + ".tmp"
    
    # 1. Backup
    if not os.path.exists(backup_path):
        try:
            shutil.copy2(dll_path, backup_path)
            print(f"[+] Backup criado com sucesso: {backup_path}")
        except PermissionError:
            print(f"[X] FALHA DE PERMISSÃO: Não foi possível criar o backup '{backup_path}'.")
            return False
        except Exception as e:
            print(f"[X] FALHA: Não foi possível criar o backup. Abortando. Erro: {e}")
            return False
    else:
        print(f"[i] Backup já existe em: {backup_path} (Pulando criação)")

    # 2. Ler DLL inteira para a memória
    print("[*] Lendo DLL para a memória para patch atômico...")
    try:
        with open(dll_path, 'rb') as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"[X] FALHA: Não foi possível ler o arquivo DLL: {e}")
        return False

    # 3. Carregar PE da memória e encontrar Offsets
    try:
        pe = pefile.PE(data=data)
        
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            pointer_size = 4
            null_bytes = b'\x00' * 4
        elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
            pointer_size = 8
            null_bytes = b'\x00' * 8
        else:
            print("[X] FALHA: Arquitetura de DLL desconhecida. Abortando patch.")
            pe.close()
            return False
            
    except pefile.PEFormatError:
        print(f"[X] FALHA: A DLL parece estar corrompida. Abortando patch.")
        return False
    except Exception as e:
        print(f"[X] FALHA: Não foi possível carregar a DLL com pefile. Erro: {e}")
        return False

    offsets_to_patch = []
    all_found = True
    print("[*] Analisando IAT (em memória) para encontrar alvos de patch...")
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("[X] FALHA: A DLL não possui uma tabela de importação (IAT).")
        pe.close()
        return False

    for target_dll, target_function in TARGETS_TO_PATCH:
        found = False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() == target_dll.lower():
                for imp in entry.imports:
                    if imp.name and imp.name.lower() == target_function.lower():
                        # Este é o offset de arquivo REAL
                        iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        file_offset = pe.get_offset_from_rva(iat_rva)
                        offsets_to_patch.append((target_function, file_offset))
                        print(f"  [+] Alvo localizado: {target_function.decode():<10} -> Offset: {hex(file_offset)}")
                        found = True
                        break
                if found: break
        if not found:
            print(f"  [X] ALERTA: Função alvo não encontrada: {target_function.decode()}")
            all_found = False

    pe.close() # Libera o objeto pefile
    
    if not all_found:
        print("[X] FALHA: Nem todas as funções alvo foram encontradas. O patch foi cancelado.")
        return False

    # 4. Aplicar os Patches (em memória)
    print("[*] Aplicando patches (em memória)...")
    for func_name, offset in offsets_to_patch:
        # Verifica se já está com patch
        if data[offset:offset+pointer_size] == null_bytes:
             print(f"  [i] Função '{func_name.decode()}' já estava neutralizada.")
        else:
            # Aplica o patch no bytearray
            for i in range(pointer_size):
                data[offset + i] = 0x00
            print(f"  [+] PATCH APLICADO! Função '{func_name.decode()}' neutralizada (em memória).")
    
    # 5. Escrever em arquivo temporário e substituir (Operação Atômica)
    try:
        print(f"[*] Escrevendo DLL modificada em arquivo temporário: {temp_path}")
        with open(temp_path, 'wb') as f:
            f.write(data)
        
        # Esta é a operação atômica. Substitui o original pelo temporário.
        os.replace(temp_path, dll_path)
        
        print("[+] SUCESSO! A DLL original foi substituída atomicamente.")
        print("[+] SUCESSO! Camada 1 (Cirurgia na DLL) concluída.")
        return True
    
    except PermissionError:
        print(f"[X] FALHA DE PERMISSÃO: Não foi possível gravar/substituir a DLL '{dll_path}'.")
        print("    Certifique-se de que a Steam está 100% fechada.")
        print("    Seu Antivírus também pode estar bloqueando a modificação.")
        if os.path.exists(temp_path): os.remove(temp_path) # Limpa o lixo
        return False
    except Exception as e:
        print(f"[X] FALHA CRÍTICA ao gravar a DLL: {e}")
        if os.path.exists(temp_path): os.remove(temp_path) # Limpa o lixo
        return False

def apply_layer_2_block():
    """
    Aplica o bloqueio no arquivo hosts (Camada 2), limpando entradas antigas.
    Retorna True se bem-sucedido, False se falhar.
    """
    print("\n--- [INICIANDO CAMADA 2: BLOQUEIO DE REDE] ---")
    
    # Lista de todos os marcadores (novos e antigos) e domínios para filtrar
    ALL_MARKERS_TO_CLEAN = [HOSTS_BLOCK_MARKER] + OLD_HOSTS_MARKERS
    ALL_DOMAINS_TO_CLEAN = DOMAINS_TO_BLOCK

    new_lines = []
    cleaned_hosts = False

    try:
        if not os.path.exists(HOSTS_FILE_PATH):
            print(f"[X] FALHA: Arquivo hosts não encontrado em '{HOSTS_FILE_PATH}'.")
            return False
        
        # 1. Read all lines and filter out old blocks
        with open(HOSTS_FILE_PATH, 'r') as f:
            all_lines = f.readlines()

        for line in all_lines:
            line_lower = line.lower()
            
            # Verifica se a linha contém qualquer marcador OU qualquer domínio
            is_marker_line = any(marker.lower() in line_lower for marker in ALL_MARKERS_TO_CLEAN)
            is_domain_line = any(domain.lower() in line_lower for domain in ALL_DOMAINS_TO_CLEAN)

            if is_marker_line or is_domain_line:
                cleaned_hosts = True # Marca que estamos removendo algo
                continue # Descarta esta linha
            
            # Não é parte dos nossos blocos, mantenha
            new_lines.append(line)

        # 2. Adiciona o novo bloco limpo no final
        if cleaned_hosts:
            print("[*] Blocos de regras antigos/duplicados encontrados. Limpando...")
            # Remove linhas vazias no final, se houver, antes de adicionar nosso bloco
            while new_lines and not new_lines[-1].strip():
                new_lines.pop()

        print("[*] Adicionando regras de bloqueio novas/atualizadas ao 'hosts'...")
        
        # Adiciona o novo bloco
        new_lines.append("\n\n") 
        new_lines.append(f"{HOSTS_BLOCK_MARKER} (Adicionado por fix-steamtools em {datetime.now().strftime('%d/%m/%Y')})\n")
        for domain in DOMAINS_TO_BLOCK:
            rule = f"0.0.0.0 {domain}\n"
            new_lines.append(rule)
            print(f"  [+] Regra adicionada: {rule.strip()}")

        # 3. Sobrescreve o arquivo hosts com o conteúdo limpo
        with open(HOSTS_FILE_PATH, 'w') as f:
            f.writelines(new_lines)
        
        print("[+] SUCESSO! Camada 2 (Bloqueio de Rede) concluída e 'hosts' limpo.")
        return True

    except PermissionError:
        print(f"[X] FALHA DE PERMISSÃO: Não foi possível modificar o arquivo '{HOSTS_FILE_PATH}'.")
        print("    (Lembrete: A verificação inicial de permissão pode ter sido enganada)")
        return False
    except Exception as e:
        print(f"[X] FALHA ao modificar o arquivo hosts: {e}")
        return False

def verify_patches(dll_path):
    """
    Função de verificação final. Audita ambas as camadas e imprime um relatório.
    Retorna uma tupla (camada1_ok, camada2_ok)
    """
    print("\n" + "="*80)
    print("                  RELATÓRIO FINAL DE VERIFICAÇÃO")
    print("="*80)
    
    camada1_ok = True
    camada2_ok = True

    # --- Verificação da Camada 1 (DLL) ---
    print("\n[*] Auditando Camada 1 (DLL)...")
    try:
        pe = pefile.PE(dll_path)
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            pointer_size = 4; null_bytes = b'\x00' * 4
        else:
            pointer_size = 8; null_bytes = b'\x00' * 8
            
        with open(dll_path, 'rb') as f:
            for target_dll, target_function in TARGETS_TO_PATCH:
                found = False
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll.lower() == target_dll.lower():
                        for imp in entry.imports:
                            if imp.name and imp.name.lower() == target_function.lower():
                                iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                                file_offset = pe.get_offset_from_rva(iat_rva)
                                
                                f.seek(file_offset)
                                read_bytes = f.read(pointer_size)
                                
                                if read_bytes == null_bytes:
                                    print(f"  [VERIFICADO] Função '{target_function.decode()}' está neutralizada.")
                                else:
                                    print(f"  [FALHA] Função '{target_function.decode()}' NÃO está neutralizada (Bytes: {read_bytes.hex()}).")
                                    camada1_ok = False
                                found = True
                                break
                        if found: break
                if not found:
                    print(f"  [FALHA] Função '{target_function.decode()}' não foi encontrada na IAT para verificação.")
                    camada1_ok = False
        pe.close()
    except Exception as e:
        print(f"  [FALHA] Erro ao auditar a DLL: {e}")
        camada1_ok = False

    # --- Verificação da Camada 2 (Hosts) ---
    print("\n[*] Auditando Camada 2 (Arquivo Hosts)...")
    try:
        with open(HOSTS_FILE_PATH, 'r') as f:
            content = f.read()
            if HOSTS_BLOCK_MARKER not in content:
                print(f"  [FALHA] Marcador de bloqueio ({HOSTS_BLOCK_MARKER}) não encontrado.")
                camada2_ok = False
            else:
                print(f"  [VERIFICADO] Marcador de bloqueio encontrado.")
            
            for domain in DOMAINS_TO_BLOCK:
                # Normaliza espaços/tabs e checa a regra
                normalized_content = ' '.join(content.split())
                rule = f"0.0.0.0 {domain}"
                if rule not in normalized_content:
                    print(f"  [FALHA] Regra de bloqueio '{rule}' não encontrada.")
                    camada2_ok = False
                else:
                    print(f"  [VERIFICADO] Regra de bloqueio '{rule}' está ativa.")
    except Exception as e:
        print(f"  [FALHA] Erro ao ler o arquivo hosts: {e}")
        camada2_ok = False

    # --- Relatório Final (Impressão) ---
    print("\n" + "-"*80)
    if camada1_ok:
        print("🟢 STATUS CAMADA 1 (DLL): VERIFICADA. Backdoor passivo neutralizado.")
    else:
        print("🔴 STATUS CAMADA 1 (DLL): FALHA. A DLL não foi corrigida.")
        
    if camada2_ok:
        print("🟢 STATUS CAMADA 2 (Rede): VERIFICADA. Bloqueio de exfiltração está ativo.")
    else:
        print("🔴 STATUS CAMADA 2 (Rede): FALHA. O bloqueio de rede não está ativo.")
    print("-" * 80)
    
    # Retorna o status para a lógica de rollback
    return (camada1_ok, camada2_ok)

def rollback_from_backup(dll_path):
    """
    Restaura a DLL original a partir do arquivo .bak.
    """
    print("\n--- [INICIANDO ROLLBACK AUTOMÁTICO] ---")
    backup_path = dll_path + ".bak"
    
    if not os.path.exists(backup_path):
        print(f"[X] FALHA CRÍTICA DE ROLLBACK: Backup '{backup_path}' não encontrado.")
        print("    O sistema está em um estado inconsistente.")
        return

    try:
        shutil.copy2(backup_path, dll_path)
        print(f"[+] SUCESSO: A DLL foi revertida com sucesso a partir do backup.")
    except Exception as e:
        print(f"[X] FALHA CRÍTICA DE ROLLBACK: Não foi possível restaurar o backup: {e}")
        print("    Por favor, restaure manualmente o backup.")

# --- [4. PONTO DE ENTRADA PRINCIPAL] ---

def main():
    """
    Orquestra a execução completa do script.
    """
    print("="*80)
    print("      FIX-STEAMTOOLS: Neutralizador de hid.dll (v0.1.0)")
    print("="*80)
    
    # O bloco try/except principal captura qualquer erro não tratado
    try:
        # 1. Exibir disclaimer e obter consentimento
        print_disclaimer_and_get_consent()
        
        # 2. Elevar privilégios e permissões
        check_for_admin_rights()
        
        # 3. Encerrar Steam
        handle_steam_process()
        
        # 4. Localizar Steam e a DLL
        dll_path = find_steam_and_dll()
        if not dll_path:
            input("\nPressione Enter para sair.")
            sys.exit(1)

        # 5. Analisar e gerar relatório
        analysis_report = analyze_and_report(dll_path)
        if analysis_report is None:
            input("\nPressione Enter para sair.")
            sys.exit(1)
            
        # 6. Obter consentimento final para o patch
        get_user_consent_to_patch(analysis_report)
        
        # 7. Aplicar Correções (Backup está incluído na Camada 1)
        l1_success = apply_layer_1_patch(dll_path)
        l2_success = apply_layer_2_block()
        
        # 8. Verificar e reportar
        if l1_success or l2_success:
            # Só verifica se tentamos aplicar o patch
            (camada1_ok, camada2_ok) = verify_patches(dll_path)
            
            # Lógica de Rollback
            if not camada1_ok and l1_success: # Se L1 foi aplicada (l1_success) mas falhou na verificação
                rollback_from_backup(dll_path)
            
            # Exibe relatório final
            if camada1_ok and camada2_ok:
                print("\n[+] SUCESSO TOTAL! A ameaça foi neutralizada em ambas as camadas.")
            else:
                print("\n[X] FALHA NA NEUTRALIZAÇÃO. Verifique os erros acima.")
                
        else:
            print("\n[X] Nenhuma ação de correção foi bem-sucedida.")

    except Exception as e:
        print("\n" + "="*80)
        print(f"[X] ERRO INESPERADO E CRÍTICO: {e}")
        print("    Algo deu muito errado. O script será encerrado.")
        print("    Por favor, reporte este erro.")
        print("="*80)

    print("\n[+] Operação concluída.")
    input("Pressione Enter para fechar o programa.")

if __name__ == "__main__":
    main()