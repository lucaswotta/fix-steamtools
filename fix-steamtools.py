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
import re       # Importado para Análise e Nulling de Strings

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

# Alvos da Camada 1 (IAT Patching)
TARGETS_TO_PATCH_IAT = [
    (b"WS2_32.dll", b"accept"),  # Impede de *aceitar* conexões
    (b"WS2_32.dll", b"listen"),  # Impede de *ouvir* por conexões
    (b"WS2_32.dll", b"bind")     # Impede de *se ligar* a uma porta
]

# Alvos da Camada 2 (Bloqueio de Rede)
DOMAINS_TO_BLOCK = [
    "update.wudrm.com",
    "wudrm.com",
    "stools.oss-cn-shanghai.aliyuncs.com",
    "update.wudrm.com",
    "update.steamui.com"
]
# Marcador para garantir que não duplicamos as entradas no hosts
HOSTS_BLOCK_MARKER = "# [FIX-STEAMTOOLS] Bloco de domínios maliciosos"

# MARCADORES ANTIGOS PARA LIMPEZA
OLD_HOSTS_MARKERS = [
    "# [NEUTRALIZE SCRIPT]"
]

# Alvos da Camada 3 (String Nulling) - Apenas C2s conhecidos (seguro)
STRINGS_TO_NULL = [
    re.compile(b"update.wudrm.com", re.IGNORECASE),
    re.compile(b"wudrm.com", re.IGNORECASE),
    re.compile(b"stools.oss-cn-shanghai.aliyuncs.com", re.IGNORECASE),
    re.compile(b"steamui.com", re.IGNORECASE),
    re.compile(b"update.steamui.com", re.IGNORECASE)
]


# Lista para análise de funções suspeitas (para o relatório)
SUSPICIOUS_IMPORTS = {
    b"ws2_32.dll": "Alto Risco. Contém funções de rede.",
    b"crypt32.dll": "Médio Risco. Funções de criptografia/certificados.",
    b"advapi32.dll": "Médio Risco. Funções 'Crypt' (criptografia)."
}
SUSPICIOUS_ADVAPI_FUNCS_PREFIX = b"Crypt"

# Lista para Análise de Strings (para o relatório)
SUSPICIOUS_STRING_PATTERNS = {
    # Domínios C2 Conhecidos (redundante com STRINGS_TO_NULL, mas bom para relatório)
    re.compile(b"update.wudrm.com", re.IGNORECASE): "Domínio de C2 Conhecido",
    re.compile(b"wudrm.com", re.IGNORECASE): "Domínio de C2 Conhecido",
    re.compile(b"stools.oss-cn-shanghai.aliyuncs.com", re.IGNORECASE): "Domínio de C2 Conhecido",
    re.compile(b"update.steamui.com", re.IGNORECASE): "Domínio de C2 Conhecido",
    re.compile(b"steamui.com", re.IGNORECASE): "Domínio de C2 Conhecido",
    # Genéricos
    re.compile(b"powershell", re.IGNORECASE): "Possível executor de script (PowerShell)",
    re.compile(b"cmd.exe", re.IGNORECASE): "Possível executor de comando (CMD)",
    re.compile(b"http://"): "Comunicação de rede não criptografada (HTTP)"
}


# --- [3. FUNÇÕES PRINCIPAIS] ---

def print_disclaimer_and_get_consent():
    """Exibe o disclaimer e exige consentimento."""
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
    """Verifica privilégios de Administrador e permissão de escrita."""
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
        print("    Isso geralmente é causado por um Antivírus.")
        input("\nPressione Enter para sair.")
        sys.exit(1)
        
    print("[+] Permissão de escrita no 'hosts' confirmada.")


def handle_steam_process():
    """Verifica se a Steam está em execução e oferece fechá-la."""
    print("[*] Verificando se a Steam está em execução...")
    steam_found = False
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == STEAM_PROCESS_NAME:
            steam_found = True
            try:
                p = proc
                print(f"[!] ALERTA: A Steam ('{STEAM_PROCESS_NAME}') está em execução (PID: {p.pid}).")
                print("    A DLL não pode ser modificada enquanto a Steam estiver aberta.")
                
                while True:
                    choice = input("    Deseja que este script feche a Steam para você? (s/n): ").lower()
                    if choice == 's':
                        print(f"[*] Encerrando o processo {STEAM_PROCESS_NAME}...")
                        p.kill()
                        p.wait()
                        print("[+] Processo da Steam encerrado.")
                        time.sleep(2)
                        return True
                    elif choice == 'n':
                        print("[X] Por favor, feche a Steam manualmente e execute o script novamente.")
                        input("Pressione Enter para sair.")
                        sys.exit(0)
            except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                print(f"[X] Erro ao tentar acessar o processo da Steam: {e}")
                input("Pressione Enter para sair.")
                sys.exit(1)

    if not steam_found:
        print("[+] Processo da Steam não encontrado. Bom para prosseguir.")
        return True

def find_steam_and_dll():
    """Encontra o caminho de instalação da Steam e a DLL maliciosa."""
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
        return None
        
    print("[*] Procurando por DLLs alvo do SteamTools...")
    for dll_name in DLL_CANDIDATES:
        dll_path = os.path.join(steam_path, dll_name)
        if os.path.exists(dll_path):
            print(f"[+] DLL alvo encontrada: {dll_path}")
            return dll_path
            
    print(f"\n[X] FALHA: Nenhuma das DLLs alvo ({', '.join(DLL_CANDIDATES)}) foi localizada.")
    return None


def get_file_md5(filepath):
    """Calcula o hash MD5 de um arquivo."""
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
    """Calcula o hash SHA256 de um arquivo."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e:
        print(f"[!] Aviso: Não foi possível calcular o SHA256: {e}")
        return "N/A"

def scan_strings_for_report(filepath):
    """Lê o arquivo e procura por strings suspeitas (apenas para relatório)."""
    print("[*] Iniciando Análise de Strings para Relatório...")
    found_strings = []
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        
        for pattern, description in SUSPICIOUS_STRING_PATTERNS.items():
            if pattern.search(data):
                match_str = pattern.search(data).group(0).decode('ascii', errors='ignore')
                report = f"'{match_str}' (Justificativa: {description})"
                if report not in found_strings:
                    found_strings.append(report)
                    
    except Exception as e:
        print(f"[!] Aviso: Falha na Análise de Strings: {e}")
        
    return found_strings

def analyze_and_report(dll_path):
    """Analisa a DLL e salva um relatório."""
    print(f"[*] Analisando a DLL alvo: {dll_path}")
    
    if not os.path.exists(dll_path):
        print("[X] FALHA: DLL não encontrada.")
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
                    report_lines.append(f"[!] DLL Importada: {entry.dll.decode()} ({SUSPICIOUS_IMPORTS[dll_name_lower]})")
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
                        report_lines.append(f"[!] DLL Importada: {entry.dll.decode()} ({SUSPICIOUS_IMPORTS[b'advapi32.dll']})")
                        found_suspects.append(entry.dll.decode())
                        for func_name in crypto_funcs_found:
                             report_lines.append(f"    -> Função: {func_name}")
        else:
            report_lines.append("[X] A DLL não possui uma Tabela de Importação.")
        
        if not found_suspects:
             report_lines.append("\n[+] Nenhuma das DLLs de alto risco foi encontrada.")

        pe.close()
        
        # --- Análise de Strings (Nível 2) ---
        report_lines.extend([
            "\n=======================================================",
            " NÍVEL 2: STRINGS SUSPEITAS ENCONTRADAS NO ARQUIVO",
            "=======================================================\n"
        ])
        
        found_strings = scan_strings_for_report(dll_path)
        if found_strings:
            for s in found_strings:
                report_lines.append(f"[!] String Encontrada: {s}")
        else:
            report_lines.append("[+] Nenhuma string suspeita foi encontrada.")
             
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

        return "\n".join(report_lines)

    except pefile.PEFormatError:
        print(f"\n[X] FALHA: O arquivo '{dll_path}' está corrompido ou não é uma DLL válida.")
        return None
    except Exception as e:
        print(f"\n[X] FALHA: Erro desconhecido ao analisar a DLL: {e}")
        return None

def get_user_consent_to_patch(analysis_report_str):
    """Exibe o plano de ação e o relatório, e pede consentimento."""
    print("\n" + "="*80)
    print("                  RELATÓRIO DE AMEAÇA ENCONTRADA")
    print("="*80)
    print(analysis_report_str)
    print("\n" + "="*80)
    print("                      PLANO DE NEUTRALIZAÇÃO (3 CAMADAS)")
    print("="*80)
    print("Baseado na análise, a ferramenta executará as seguintes operações:")

    print("\n[AÇÃO 1: BACKUP DE SEGURANÇA]")
    print("  - Uma cópia exata da DLL será salva como 'hid.dll.bak'.")

    print("\n[AÇÃO 2: NEUTRALIZAÇÃO NA DLL (CAMADAS 1 e 3)]")
    print("  - Objetivo: Desativar backdoor e URLs maliciosas dentro da DLL.")
    print("  - Camada 1 (IAT Patching): Neutraliza funções de rede ('accept', 'listen', 'bind').")
    print("  - Camada 3 (String Nulling): Zera domínios C2 hardcoded dentro da DLL.")
    print(f"    Strings Alvo: {', '.join([p.pattern.decode('ascii', errors='ignore') for p in STRINGS_TO_NULL])}")

    print("\n[AÇÃO 3: BLOQUEIO DE REDE (CAMADA 2)]")
    print("  - Objetivo: Impedir conexões de saída para servidores C2.")
    print("  - Método: Adiciona regras ao arquivo 'hosts' do Windows.")
    print("  - Domínios Bloqueados:")
    for domain in DOMAINS_TO_BLOCK:
        print(f"    - {domain}")

    print("\n[AÇÃO 4: VERIFICAÇÃO E ROLLBACK AUTOMÁTICO]")
    print("  - Após a operação, o script auditará se todas as 3 camadas foram aplicadas.")
    print("  - Se a verificação da DLL (L1 ou L3) falhar, o backup será restaurado.")
        
    print("\n" + "="*80)
    
    try:
        input("Pressione [ENTER] para INICIAR a neutralização ou [CTRL+C] para cancelar...")
        print("Iniciando operação...")
    except KeyboardInterrupt:
        print("\n\n[X] Operação cancelada pelo usuário.")
        sys.exit(0)

# --- NOVA FUNÇÃO v0.2.1 ---
def apply_layer_3_string_nulling(data: bytearray) -> int:
    """
    CAMADA 3: STRING NULLING
    Procura por URLs/domínios C2 hardcoded e os sobrescreve com zeros.
    Opera diretamente no bytearray em memória.
    Retorna o número de strings neutralizadas.
    """
    print("\n--- [INICIANDO CAMADA 3: STRING NULLING (EM MEMÓRIA)] ---")
    neutralized_count = 0
    
    for pattern in STRINGS_TO_NULL:
        # Usamos finditer para encontrar todas as ocorrências
        for match in pattern.finditer(bytes(data)):
            start = match.start()
            end = match.end()
            matched_string = data[start:end].decode('ascii', errors='ignore')
            
            # Zera os bytes correspondentes na DLL em memória
            for i in range(start, end):
                data[i] = 0x00
            
            print(f"  [+] String C2 neutralizada: '{matched_string}' (offset: {hex(start)})")
            neutralized_count += 1
            
    if neutralized_count > 0:
        print(f"[+] CAMADA 3 CONCLUÍDA (EM MEMÓRIA): {neutralized_count} strings C2 neutralizadas.")
    else:
        print("[i] Nenhuma string C2 alvo encontrada para Camada 3.")
        
    return neutralized_count


# --- MODIFICADA v0.2.1 ---
def apply_dll_patches(dll_path):
    """
    Aplica as Camadas 1 (IAT) e 3 (String Nulling) de forma atômica.
    Retorna True se bem-sucedido, False se falhar.
    """
    print("\n--- [INICIANDO PATCH ATÔMICO NA DLL (CAMADAS 1 e 3)] ---")
    
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
            print(f"[X] FALHA: Não foi possível criar o backup. Erro: {e}")
            return False
    else:
        print(f"[i] Backup já existe em: {backup_path} (Pulando criação)")

    # 2. Ler DLL para a memória
    print("[*] Lendo DLL para a memória...")
    try:
        with open(dll_path, 'rb') as f:
            data = bytearray(f.read())
    except Exception as e:
        print(f"[X] FALHA: Não foi possível ler o arquivo DLL: {e}")
        return False

    # 3. Carregar PE da memória e encontrar Offsets IAT (Camada 1)
    try:
        pe = pefile.PE(data=data)
        
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            pointer_size = 4; null_bytes = b'\x00' * 4
        else:
            pointer_size = 8; null_bytes = b'\x00' * 8
            
    except pefile.PEFormatError:
        print(f"[X] FALHA: A DLL parece estar corrompida.")
        return False
    except Exception as e:
        print(f"[X] FALHA: Não foi possível carregar a DLL com pefile. Erro: {e}")
        return False

    offsets_to_patch = []
    all_found = True
    print("[*] Analisando IAT (em memória) para Camada 1...")
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        print("[X] FALHA: A DLL não possui uma tabela de importação (IAT).")
        pe.close()
        return False

    for target_dll, target_function in TARGETS_TO_PATCH_IAT:
        found = False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() == target_dll.lower():
                for imp in entry.imports:
                    if imp.name and imp.name.lower() == target_function.lower():
                        iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                        file_offset = pe.get_offset_from_rva(iat_rva)
                        offsets_to_patch.append((target_function, file_offset))
                        print(f"  [+] Alvo L1 localizado: {target_function.decode():<10} -> Offset: {hex(file_offset)}")
                        found = True
                        break
                if found: break
        if not found:
            print(f"  [X] ALERTA: Função alvo L1 não encontrada: {target_function.decode()}")
            all_found = False

    pe.close() # Libera o objeto pefile
    
    if not all_found:
        print("[X] FALHA: Nem todas as funções alvo L1 foram encontradas. Patch cancelado.")
        return False

    # 4. Aplicar Patches IAT (Camada 1 - em memória)
    print("[*] Aplicando patches da Camada 1 (em memória)...")
    l1_applied_count = 0
    for func_name, offset in offsets_to_patch:
        if data[offset:offset+pointer_size] != null_bytes:
            for i in range(pointer_size):
                data[offset + i] = 0x00
            print(f"  [+] L1 PATCH APLICADO! Função '{func_name.decode()}' neutralizada.")
            l1_applied_count += 1
        else:
             print(f"  [i] L1: Função '{func_name.decode()}' já estava neutralizada.")
             
    # 5. Aplicar String Nulling (Camada 3 - em memória)
    # Chamamos a função separada que opera no mesmo bytearray 'data'
    l3_applied_count = apply_layer_3_string_nulling(data)
    
    # 6. Escrever em arquivo temporário e substituir (Operação Atômica)
    if l1_applied_count > 0 or l3_applied_count > 0:
        try:
            print(f"\n[*] Escrevendo DLL modificada (L1+L3) em arquivo temporário: {temp_path}")
            with open(temp_path, 'wb') as f:
                f.write(data)
            
            os.replace(temp_path, dll_path)
            
            print("[+] SUCESSO! A DLL original foi substituída atomicamente.")
            print("[+] SUCESSO! Patches na DLL (Camadas 1 e 3) concluídos.")
            return True
        
        except PermissionError:
            print(f"[X] FALHA DE PERMISSÃO: Não foi possível gravar/substituir a DLL '{dll_path}'.")
            if os.path.exists(temp_path): os.remove(temp_path)
            return False
        except Exception as e:
            print(f"[X] FALHA CRÍTICA ao gravar a DLL: {e}")
            if os.path.exists(temp_path): os.remove(temp_path)
            return False
    else:
        print("[i] Nenhum patch L1 ou L3 foi necessário (DLL já parecia neutralizada).")
        return True # Consideramos sucesso, pois não havia nada a fazer


def apply_layer_2_block():
    """Aplica o bloqueio no arquivo hosts (Camada 2), limpando entradas antigas."""
    print("\n--- [INICIANDO CAMADA 2: BLOQUEIO DE REDE] ---")
    
    ALL_MARKERS_TO_CLEAN = [HOSTS_BLOCK_MARKER] + OLD_HOSTS_MARKERS
    ALL_DOMAINS_TO_CLEAN = DOMAINS_TO_BLOCK

    new_lines = []
    cleaned_hosts = False

    try:
        if not os.path.exists(HOSTS_FILE_PATH):
            print(f"[X] FALHA: Arquivo hosts não encontrado.")
            return False
        
        # 1. Ler e filtrar
        with open(HOSTS_FILE_PATH, 'r') as f:
            all_lines = f.readlines()

        for line in all_lines:
            line_strip = line.strip()
            if not line_strip: # Pula linhas vazias
                 new_lines.append(line)
                 continue

            line_lower = line_strip.lower()
            
            is_marker_line = any(marker.lower() in line_lower for marker in ALL_MARKERS_TO_CLEAN)
            is_domain_line = any(domain.lower() in line_lower for domain in ALL_DOMAINS_TO_CLEAN if line_strip.startswith('0.0.0.0')) # Checa se começa com 0.0.0.0

            if is_marker_line or is_domain_line:
                if not cleaned_hosts: # Imprime só na primeira vez
                     print("[*] Blocos de regras antigos/duplicados encontrados. Limpando...")
                cleaned_hosts = True
                continue # Descarta
            
            new_lines.append(line)

        # 2. Adiciona o novo bloco
        # Remove linhas vazias no final antes de adicionar
        while new_lines and not new_lines[-1].strip():
            new_lines.pop()

        print("[*] Adicionando regras de bloqueio novas/atualizadas ao 'hosts'...")
        
        new_lines.append("\n\n") 
        new_lines.append(f"{HOSTS_BLOCK_MARKER} (Adicionado por fix-steamtools em {datetime.now().strftime('%d/%m/%Y')})\n")
        for domain in DOMAINS_TO_BLOCK:
            rule = f"0.0.0.0 {domain}\n"
            new_lines.append(rule)
            print(f"  [+] Regra adicionada: {rule.strip()}")

        # 3. Sobrescreve
        with open(HOSTS_FILE_PATH, 'w') as f:
            f.writelines(new_lines)
        
        print("[+] SUCESSO! Camada 2 (Bloqueio de Rede) concluída e 'hosts' limpo.")
        return True

    except PermissionError:
        print(f"[X] FALHA DE PERMISSÃO: Não foi possível modificar o arquivo '{HOSTS_FILE_PATH}'.")
        return False
    except Exception as e:
        print(f"[X] FALHA ao modificar o arquivo hosts: {e}")
        return False

# --- MODIFICADA v0.2.1 ---
def verify_patches(dll_path):
    """Função de verificação final. Audita as 3 camadas."""
    print("\n" + "="*80)
    print("                  RELATÓRIO FINAL DE VERIFICAÇÃO")
    print("="*80)
    
    camada1_ok = True
    camada2_ok = True
    camada3_ok = True # Nova camada

    # --- Verificação da Camada 1 (IAT) ---
    print("\n[*] Auditando Camada 1 (IAT Patching)...")
    try:
        pe = pefile.PE(dll_path)
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
            pointer_size = 4; null_bytes = b'\x00' * 4
        else:
            pointer_size = 8; null_bytes = b'\x00' * 8
            
        with open(dll_path, 'rb') as f:
            for target_dll, target_function in TARGETS_TO_PATCH_IAT:
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
                                    print(f"  [VERIFICADO] L1: Função '{target_function.decode()}' está neutralizada.")
                                else:
                                    print(f"  [FALHA] L1: Função '{target_function.decode()}' NÃO neutralizada.")
                                    camada1_ok = False
                                found = True
                                break
                        if found: break
                if not found:
                    print(f"  [FALHA] L1: Função '{target_function.decode()}' não encontrada na IAT.")
                    camada1_ok = False
        pe.close()
    except Exception as e:
        print(f"  [FALHA] L1: Erro ao auditar a DLL: {e}")
        camada1_ok = False

    # --- Verificação da Camada 2 (Hosts) ---
    print("\n[*] Auditando Camada 2 (Arquivo Hosts)...")
    try:
        with open(HOSTS_FILE_PATH, 'r') as f:
            content = f.read()
            if HOSTS_BLOCK_MARKER not in content:
                print(f"  [FALHA] L2: Marcador de bloqueio não encontrado.")
                camada2_ok = False
            else:
                print(f"  [VERIFICADO] L2: Marcador de bloqueio encontrado.")
            
            for domain in DOMAINS_TO_BLOCK:
                normalized_content = ' '.join(content.split())
                rule = f"0.0.0.0 {domain}"
                if rule not in normalized_content:
                    print(f"  [FALHA] L2: Regra de bloqueio '{rule}' não encontrada.")
                    camada2_ok = False
                else:
                    print(f"  [VERIFICADO] L2: Regra de bloqueio '{rule}' está ativa.")
    except Exception as e:
        print(f"  [FALHA] L2: Erro ao ler o arquivo hosts: {e}")
        camada2_ok = False
        
    # --- Verificação da Camada 3 (String Nulling) ---
    print("\n[*] Auditando Camada 3 (String Nulling)...")
    try:
        with open(dll_path, 'rb') as f:
            data = f.read()
        
        found_malicious_string = False
        for pattern in STRINGS_TO_NULL:
            if pattern.search(data):
                match_str = pattern.search(data).group(0).decode('ascii', errors='ignore')
                print(f"  [FALHA] L3: String C2 '{match_str}' ainda presente na DLL!")
                camada3_ok = False
                found_malicious_string = True
                # Poderia adicionar break aqui se uma falha for suficiente
                
        if not found_malicious_string:
            print("  [VERIFICADO] L3: Nenhuma string C2 alvo encontrada (neutralizadas com sucesso).")
            
    except Exception as e:
        print(f"  [FALHA] L3: Erro na verificação de strings: {e}")
        camada3_ok = False

    # --- Relatório Final (Impressão) ---
    print("\n" + "-"*80)
    if camada1_ok: print("🟢 STATUS CAMADA 1 (IAT): VERIFICADA.")
    else: print("🔴 STATUS CAMADA 1 (IAT): FALHA.")
        
    if camada2_ok: print("🟢 STATUS CAMADA 2 (Hosts): VERIFICADA.")
    else: print("🔴 STATUS CAMADA 2 (Hosts): FALHA.")
        
    if camada3_ok: print("🟢 STATUS CAMADA 3 (Strings): VERIFICADA.")
    else: print("🔴 STATUS CAMADA 3 (Strings): FALHA.")
    print("-" * 80)
    
    # Retorna o status para a lógica de rollback
    return (camada1_ok, camada2_ok, camada3_ok)

def rollback_from_backup(dll_path):
    """Restaura a DLL original a partir do arquivo .bak."""
    print("\n--- [INICIANDO ROLLBACK AUTOMÁTICO] ---")
    backup_path = dll_path + ".bak"
    
    if not os.path.exists(backup_path):
        print(f"[X] FALHA CRÍTICA DE ROLLBACK: Backup '{backup_path}' não encontrado.")
        return

    try:
        shutil.copy2(backup_path, dll_path)
        print(f"[+] SUCESSO: A DLL foi revertida com sucesso a partir do backup.")
    except Exception as e:
        print(f"[X] FALHA CRÍTICA DE ROLLBACK: Não foi possível restaurar o backup: {e}")

# --- [4. PONTO DE ENTRADA PRINCIPAL] ---

def main():
    """Orquestra a execução completa do script."""
    print("="*80)
    print("      FIX-STEAMTOOLS: Neutralizador de hid.dll (v0.2.1)")
    print("="*80)
    
    try:
        # 1. Disclaimer e Consentimento
        print_disclaimer_and_get_consent()
        
        # 2. Privilégios e Permissões
        check_for_admin_rights()
        
        # 3. Encerrar Steam
        handle_steam_process()
        
        # 4. Localizar Steam e DLL
        dll_path = find_steam_and_dll()
        if not dll_path:
            input("\nPressione Enter para sair.")
            sys.exit(1)

        # 5. Análise e Relatório
        analysis_report = analyze_and_report(dll_path)
        if analysis_report is None:
            input("\nPressione Enter para sair.")
            sys.exit(1)
            
        # 6. Consentimento Final para Patch
        get_user_consent_to_patch(analysis_report)
        
        # 7. Aplicar Correções (L1 e L3 são atômicas juntas, L2 separada)
        l1l3_success = apply_dll_patches(dll_path) # Camadas 1 e 3
        l2_success = apply_layer_2_block()       # Camada 2
        
        # 8. Verificar e Reportar
        if l1l3_success or l2_success:
            (camada1_ok, camada2_ok, camada3_ok) = verify_patches(dll_path)
            
            # Lógica de Rollback: Se o patch DLL (L1+L3) foi tentado (l1l3_success)
            # mas a verificação de L1 OU L3 falhou, reverta.
            if l1l3_success and (not camada1_ok or not camada3_ok):
                rollback_from_backup(dll_path)
            
            # Exibe relatório final
            if all([camada1_ok, camada2_ok, camada3_ok]):
                print("\n[+] SUCESSO TOTAL! A ameaça foi neutralizada nas 3 camadas.")
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