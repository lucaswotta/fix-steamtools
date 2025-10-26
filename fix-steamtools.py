import os
import sys
import subprocess
import ctypes
import shutil
from datetime import datetime
import time
import platform
import hashlib
import winreg
import re
import traceback

# --- [1. VERIFICAÇÃO DE DEPENDÊNCIAS (Terceiros)] ---
try:
    import pefile
    import psutil
except ImportError:
    print("[-] Dependências (pefile, psutil) não encontradas.")
    print("[*] Tentando instalar via 'pip'...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", "pip"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile", "psutil"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("\n[+] Dependências instaladas com sucesso.")
        import pefile
        import psutil
    except Exception as e:
        print(f"\n[X] FALHA CRÍTICA ao instalar dependências: {e}")
        print("    Verifique sua conexão ou instale manualmente: pip install pefile psutil")
        input("Pressione Enter para sair."); sys.exit(1)


# --- [2. CONFIGURAÇÃO GLOBAL DE ALVOS] ---

HOSTS_FILE_PATH = r"C:\Windows\System32\drivers\etc\hosts"
STEAM_PROCESS_NAME = "steam.exe"
DLL_CANDIDATES = ["hid.dll", "hid64.dll", "hid32.dll"]

TARGETS_TO_PATCH_IAT = [
    (b"WS2_32.dll", b"accept"), (b"WS2_32.dll", b"listen"), (b"WS2_32.dll", b"bind")
]

DOMAINS_TO_BLOCK = sorted(list(set([
    "update.wudrm.com", "stools.oss-cn-shanghai.aliyuncs.com",
    "steamtools.info", "steamtools.net", "steamtoos.net",
    "new-service.biliapi.net",
])))

# Marcador simplificado - apenas identificador, sem data/versão
HOSTS_BLOCK_MARKER = "# [FIX-STEAMTOOLS]"

# Marcadores antigos para limpeza (incluindo versões antigas com data/versão)
OLD_HOSTS_MARKERS_LOWER = [
    "# [neutralize script]",
    "# [fix-steamtools] bloco de domnios maliciosos",  # Typo antigo
    "# [fix-steamtools] bloco de domínios maliciosos",  # Versão antiga completa
]
CURRENT_MARKER_BASE_LOWER = HOSTS_BLOCK_MARKER.lower()

STRINGS_TO_NULL = [
    re.compile(b"update.wudrm.com", re.IGNORECASE),
    re.compile(b"stools.oss-cn-shanghai.aliyuncs.com", re.IGNORECASE),
    re.compile(b"steamtools.info", re.IGNORECASE),
    re.compile(b"steamtools.net", re.IGNORECASE),
    re.compile(b"steamtoos.net", re.IGNORECASE),
    re.compile(b"new-service.biliapi.net", re.IGNORECASE),
]

SUSPICIOUS_IMPORTS = {
    b"ws2_32.dll": "Alto Risco (Rede)", b"crypt32.dll": "Médio Risco (Cripto)",
    b"advapi32.dll": "Médio Risco (Cripto)"
}
SUSPICIOUS_ADVAPI_FUNCS_PREFIX = b"Crypt"

SUSPICIOUS_STRING_PATTERNS = {
    re.compile(b"update.wudrm.com", re.IGNORECASE): "Domínio C2/Infra",
    re.compile(b"stools.oss-cn-shanghai.aliyuncs.com", re.IGNORECASE): "Domínio C2/Infra",
    re.compile(b"steamtools.info", re.IGNORECASE): "Domínio C2/Infra",
    re.compile(b"steamtools.net", re.IGNORECASE): "Domínio C2/Infra",
    re.compile(b"steamtoos.net", re.IGNORECASE): "Domínio C2/Infra (Typo)",
    re.compile(b"new-service.biliapi.net", re.IGNORECASE): "Domínio C2/Infra (Bilibili)",
    re.compile(b"powershell", re.IGNORECASE): "Executor Script",
    re.compile(b"cmd.exe", re.IGNORECASE): "Executor Comando",
    re.compile(b"http://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"): "IP (HTTP)",
    re.compile(b"LoadLibrary", re.IGNORECASE): "Load Dinâmico DLL",
    re.compile(b"GetProcAddress", re.IGNORECASE): "Get Dinâmico Função",
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
            print("[+] Consentimento aceito.")
            time.sleep(1)
        else:
            print("[X] Consentimento não fornecido. Saindo."); sys.exit(0)

    except KeyboardInterrupt:
        print("\n[X] Operação cancelada."); sys.exit(0)

def print_first_run_warning():
    """Exibe o aviso sobre a necessidade da primeira execução."""
    print("\n" + "="*80)
    print("         ⚠️ AVISO CRÍTICO SOBRE A PRIMEIRA EXECUÇÃO ⚠️")
    print("="*80)
    print("Se esta é a sua PRIMEIRA VEZ utilizando o SteamTools (ou similar),")
    print("pode ser necessário executar o programa original UMA ÚNICA VEZ para")
    print("que ele crie arquivos/configurações essenciais para funcionar.")
    print("\nRECOMENDAÇÃO:")
    print("1. Execute o SteamTools original UMA VEZ.")
    print("2. Feche a Steam IMEDIATAMENTE.")
    print("3. Execute este script (`fix-steamtools`) para neutralizar a DLL.")
    print("4. NÃO ABRA MAIS o SteamTools original após usar este fix.")
    print("="*80)
    try:
        input("Pressione Enter para confirmar que leu este aviso...")
    except KeyboardInterrupt:
        print("\n[X] Operação cancelada."); sys.exit(0)


def check_for_admin_rights():
    """Verifica privilégios de Administrador e permissão de escrita."""
    print("[*] Verificando privilégios de Administrador...")
    is_admin = False
    try: is_admin = (os.getuid() == 0)
    except AttributeError:
        try: is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e: print(f"[!] Aviso ctypes: {e}")
    if not is_admin: print("\n[X] FALHA: Requer privilégios de Administrador."); input("Sair."); sys.exit(1)
    print("[+] Privilégios de Administrador OK.")

    print("[*] Verificando permissão de escrita no 'hosts'...")
    try:
        temp_file = HOSTS_FILE_PATH + ".fix_perm_test"; f = open(temp_file, "w"); f.write("test"); f.close(); os.remove(temp_file)
        print("[+] Permissão de escrita OK.")
    except Exception as e:
        print(f"\n[X] FALHA PERMISSÃO REAL: Não pode escrever na pasta do hosts ({e})")
        print("    Causa provável: Antivírus."); input("Sair."); sys.exit(1)


def handle_steam_process():
    """Verifica se a Steam está em execução e oferece fechá-la."""
    print("[*] Verificando processo Steam...")
    steam_pid = None; process_name_lower = STEAM_PROCESS_NAME.lower()
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            proc_name = proc.info['name']
            if proc_name and proc_name.lower() == process_name_lower:
                steam_pid = proc.info['pid']; break
        except Exception: continue

    if steam_pid:
        try:
            p = psutil.Process(steam_pid)
            print(f"[!] ALERTA: Steam ativa (PID: {steam_pid}).")
            while True:
                choice = input("    Deseja fechar agora? (s/n): ").lower()
                if choice == 's':
                    print(f"[*] Encerrando Steam...")
                    p.terminate(); p.wait(timeout=3)
                    print("[+] Processo Steam encerrado."); time.sleep(2); return True
                elif choice == 'n': print("[X] Feche manualmente e reexecute."); input("Sair."); sys.exit(0)
        except Exception as e: print(f"[X] Erro ao encerrar Steam: {e}"); input("Sair."); sys.exit(1)
    else: print("[+] Processo Steam não encontrado."); return True

def find_steam_and_dll():
    """Encontra o caminho de instalação da Steam e a DLL maliciosa."""
    print("[*] Localizando pasta da Steam...")
    registry_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Valve\Steam", winreg.KEY_READ),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Valve\Steam", winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", winreg.KEY_READ),
        (winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam", winreg.KEY_READ | winreg.KEY_WOW64_32KEY)
    ]
    steam_path = None
    for hkey, path, access_mask in registry_paths:
        try:
            with winreg.OpenKey(hkey, path, 0, access_mask) as key:
                install_path, reg_type = winreg.QueryValueEx(key, "InstallPath")
                if reg_type == winreg.REG_SZ and install_path and os.path.isdir(install_path):
                    print(f"[+] Steam encontrada: {install_path}"); steam_path = install_path; break
        except Exception: continue
    if not steam_path: print("\n[X] FALHA: Pasta da Steam não localizada."); return None

    print("[*] Procurando DLLs alvo...")
    for dll_name in DLL_CANDIDATES:
        dll_path = os.path.join(steam_path, dll_name)
        if os.path.isfile(dll_path): print(f"[+] DLL alvo: {dll_path}"); return dll_path
    print(f"\n[X] FALHA: Nenhuma DLL alvo encontrada."); return None


def get_file_md5(filepath):
    """Calcula o hash MD5 de um arquivo."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e: print(f"[!] Aviso MD5: {e}"); return "N/A"

def get_file_sha256(filepath):
    """Calcula o hash SHA256 de um arquivo."""
    hash_sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""): hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except Exception as e: print(f"[!] Aviso SHA256: {e}"); return "N/A"

def scan_strings_for_report(filepath):
    """Lê o arquivo e procura por strings suspeitas (apenas para relatório)."""
    print("[*] Iniciando Análise de Strings para Relatório...")
    found_strings_dict = {}
    min_len = 5

    try:
        with open(filepath, 'rb') as f: data = f.read()

        strings = set()
        # ASCII
        for match in re.finditer(b"[\x20-\x7E]{%d,}" % min_len, data):
            try: strings.add(match.group(0).decode('ascii').strip())
            except UnicodeDecodeError: pass
        # Unicode (UTF-16LE)
        for match in re.finditer(b"(?:[\x20-\x7E]\x00){%d,}" % min_len, data):
            try: strings.add(match.group(0).decode('utf-16le').strip('\x00').strip())
            except UnicodeDecodeError: pass

        # Compara com padrões
        for s in strings:
             if not s: continue
             s_bytes_check = s.encode('utf-8', errors='ignore')
             for pattern, description in SUSPICIOUS_STRING_PATTERNS.items():
                  if pattern.search(s_bytes_check):
                       report = f"'{s}' ({description})"
                       if (s, description) not in found_strings_dict:
                            found_strings_dict[(s, description)] = report

    except FileNotFoundError: print(f"[X] Erro Strings: Arquivo não encontrado.")
    except Exception as e: print(f"[!] Aviso Strings: {e}")

    return list(found_strings_dict.values())


def analyze_and_report(dll_path):
    """Analisa a DLL e salva um relatório."""
    print(f"[*] Analisando DLL: {os.path.basename(dll_path)}")

    if not os.path.exists(dll_path): print("[X] FALHA: DLL não encontrada."); return None
    if os.path.getsize(dll_path) < 1024: print("[X] FALHA: DLL muito pequena/vazia."); return None

    report_lines = [] ; report_path = ""

    try:
        pe = pefile.PE(dll_path)

        signature_status = "NÃO ASSINADA (SUSPEITO)"
        try:
            sec_dir_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_index and \
               pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_index].Size > 0:
                signature_status = "ASSINADA DIGITALMENTE (Inesperado!)"
                print("[!] ALERTA: DLL parece assinada.")
        except Exception: pass

        report_lines = [
            f"Relatório Análise: {dll_path}", f"Data: {datetime.now():%d/%m/%Y %H:%M:%S}",
            f"Tamanho: {os.path.getsize(dll_path)} bytes", f"MD5: {get_file_md5(dll_path)}",
            f"SHA256: {get_file_sha256(dll_path)}", f"Assinatura: {signature_status}",
        ]

        # --- Nível 1: Importações ---
        report_lines.extend(["\n" + "="*55, " NÍVEL 1: IMPORTAÇÕES SUSPEITAS", "="*55 + "\n"])
        found_suspects = [] ; max_funcs = 8

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name_lower = entry.dll.lower(); dll_name = entry.dll.decode(errors='ignore')
                if dll_name_lower in SUSPICIOUS_IMPORTS:
                    report_lines.append(f"[!] DLL: {dll_name} ({SUSPICIOUS_IMPORTS[dll_name_lower]})")
                    found_suspects.append(dll_name)
                    funcs = [imp.name.decode(errors='ignore') for imp in entry.imports if imp.name][:max_funcs]
                    for func in funcs: report_lines.append(f"    -> {func}")
                    if len(entry.imports) > max_funcs: report_lines.append(f"    -> ... (+{len(entry.imports) - max_funcs})")

                elif dll_name_lower == b"advapi32.dll":
                    crypto_funcs = [imp.name.decode(errors='ignore') for imp in entry.imports if imp.name and imp.name.lower().startswith(SUSPICIOUS_ADVAPI_FUNCS_PREFIX.lower())]
                    if crypto_funcs:
                        report_lines.append(f"[!] DLL: {dll_name} ({SUSPICIOUS_IMPORTS[b'advapi32.dll']})")
                        found_suspects.append(dll_name)
                        for func in crypto_funcs[:max_funcs]: report_lines.append(f"    -> {func}")
                        if len(crypto_funcs) > max_funcs: report_lines.append(f"    -> ... (+{len(crypto_funcs) - max_funcs})")
        else: report_lines.append("[X] Tabela Import não encontrada.")
        if not found_suspects: report_lines.append("\n[+] Nenhuma DLL de risco encontrada.")

        pe.close()

        # --- Nível 2: Strings ---
        report_lines.extend(["\n" + "="*55, " NÍVEL 2: STRINGS SUSPEITAS", "="*55 + "\n"])
        found_strings = scan_strings_for_report(dll_path)
        if found_strings:
            for s in found_strings: report_lines.append(f"[!] {s}")
        else: report_lines.append("[+] Nenhuma string suspeita encontrada.")

        # --- Salvar Relatório ---
        report_filename = f"fix-steamtools_analise_{datetime.now():%d%m%Y_%H%M%S}.txt"
        report_path = os.path.join(os.path.dirname(sys.argv[0] or '.'), report_filename)
        try:
            report_lines_str = [str(line) for line in report_lines]
            with open(report_path, 'w', encoding='utf-8') as f: f.write("\n".join(report_lines_str))
            saved_msg = f"Relatório salvo em: {report_path}"
            print(f"[+] {saved_msg}")
            report_lines_str.insert(0, f"{saved_msg}\n")
            return "\n".join(report_lines_str)
        except Exception as e:
            print(f"[X] FALHA ao salvar relatório: {e}")
            return "\n".join(report_lines_str)

    except pefile.PEFormatError: print(f"\n[X] FALHA: Arquivo corrompido/inválido."); return None
    except Exception as e: print(f"\n[X] FALHA: Erro análise DLL: {e}"); return None

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
    print("  - Uma cópia exata da DLL será salva como '.bak'.")
    print("\n[AÇÃO 2: NEUTRALIZAÇÃO NA DLL (CAMADAS 1 e 3)]")
    print("  - Objetivo: Desativar backdoor e URLs maliciosas dentro da DLL.")
    print("  - Camada 1 (IAT Patching): Neutraliza 'accept', 'listen', 'bind'.")
    print("  - Camada 3 (String Nulling): Zera domínios C2/Infra hardcoded.")
    print(f"    Strings Alvo: {', '.join([p.pattern.decode('ascii', errors='ignore') for p in STRINGS_TO_NULL])}")
    print("\n[AÇÃO 3: BLOQUEIO DE REDE (CAMADA 2)]")
    print("  - Objetivo: Impedir conexões de saída para servidores C2/Infra.")
    print("  - Método: Adiciona/Atualiza regras no arquivo 'hosts'.")
    print("  - Domínios Bloqueados:")
    for domain in DOMAINS_TO_BLOCK: print(f"    - {domain}")
    print("\n[AÇÃO 4: VERIFICAÇÃO E ROLLBACK AUTOMÁTICO]")
    print("  - Após a operação, auditará se todas as 3 camadas foram aplicadas.")
    print("  - Se a verificação da DLL (L1 ou L3) falhar, o backup será restaurado.")
    print("\n" + "="*80)
    try:
        input("Pressione [ENTER] para INICIAR ou [CTRL+C] para cancelar...")
        print("Iniciando operação...")
    except KeyboardInterrupt: print("\n\n[X] Operação cancelada."); sys.exit(0)

def apply_layer_3_string_nulling(data: bytearray) -> int:
    """
    CAMADA 3: STRING NULLING - Zera strings alvo em memória.
    Retorna contagem.
    """
    print("\n--- [INICIANDO CAMADA 3: STRING NULLING (EM MEMÓRIA)] ---")
    neutralized_count = 0
    replacement_byte = 0x00

    indices_to_patch = []
    for pattern in STRINGS_TO_NULL:
        for match in pattern.finditer(bytes(data)):
            indices_to_patch.append((match.start(), match.end(), match.group(0)))
    indices_to_patch.sort(key=lambda x: x[0])

    last_end = -1
    for start, end, original_bytes in indices_to_patch:
         if start < last_end: continue
         if start >= len(data) or end > len(data):
              print(f"[!] Aviso L3: Match fora dos limites ({hex(start)}-{hex(end)}). Pulando."); continue

         if all(data[i] == replacement_byte for i in range(start, end)): continue

         matched_string_decoded = original_bytes.decode('ascii', errors='ignore')
         for i in range(start, end): data[i] = replacement_byte
         print(f"  [+] L3 PATCH: String '{matched_string_decoded}' neutralizada (offset: {hex(start)})")
         neutralized_count += 1
         last_end = end

    if neutralized_count > 0: print(f"[+] CAMADA 3 CONCLUÍDA: {neutralized_count} strings neutralizadas.")
    else: print("[i] L3: Nenhuma string alvo encontrada/modificada.")
    return neutralized_count


def apply_dll_patches(dll_path):
    """Aplica Camadas 1 (IAT) e 3 (String Nulling) atomicamente."""
    print("\n--- [INICIANDO PATCH ATÔMICO NA DLL (L1 + L3)] ---")
    backup_path = dll_path + ".bak"; temp_path = dll_path + ".tmp"

    # 1. Backup
    if not os.path.exists(backup_path):
        try: shutil.copy2(dll_path, backup_path); print(f"[+] Backup criado.")
        except Exception as e: print(f"[X] FALHA Backup: {e}"); return False
    else: print(f"[i] Backup já existe.")

    # 2. Ler DLL
    print("[*] Lendo DLL..."); data = None
    try:
        with open(dll_path, 'rb') as f: data = bytearray(f.read())
        if not data: print("[X] FALHA: DLL vazia."); return False
    except Exception as e: print(f"[X] FALHA Leitura DLL: {e}"); return False

    # 3. Carregar PE e encontrar Offsets IAT (L1)
    try:
        pe = pefile.PE(data=data)
        if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: pointer_size = 4; null_bytes = b'\x00' * 4
        else: pointer_size = 8; null_bytes = b'\x00' * 8
    except Exception as e: print(f"[X] FALHA Carregar PE: {e}"); return False

    offsets_to_patch = []; l1_all_found = True
    print("[*] Analisando IAT (L1)...")
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'): print("[X] FALHA L1: IAT não encontrada."); pe.close(); return False

    for target_dll, target_function in TARGETS_TO_PATCH_IAT:
        found = False
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll.lower() == target_dll.lower():
                for imp in entry.imports:
                    if imp.name and imp.name.lower() == target_function.lower():
                        try:
                             iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                             file_offset = pe.get_offset_from_rva(iat_rva)
                             if not (0 <= file_offset < len(data) - pointer_size): raise ValueError("Offset inválido")
                             offsets_to_patch.append((target_function, file_offset))
                             found = True; break
                        except Exception as offset_e: print(f"  [X] ERRO L1 Offset '{target_function.decode()}': {offset_e}"); l1_all_found = False; found = True; break
                if found: break
        if not found and l1_all_found: print(f"  [X] ALERTA L1: '{target_function.decode()}' não encontrada."); l1_all_found = False

    pe.close()
    if not l1_all_found: print("[X] FALHA L1: Alvos inválidos/não encontrados."); return False

    # 4. Aplicar Patches IAT (L1 - em memória)
    print("[*] Aplicando patches L1...")
    l1_applied_count = 0
    for func_name, offset in offsets_to_patch:
        if data[offset:offset+pointer_size] != null_bytes:
            for i in range(pointer_size): data[offset + i] = 0x00
            print(f"  [+] L1 PATCH: '{func_name.decode()}' neutralizada.")
            l1_applied_count += 1

    # 5. Aplicar String Nulling (L3 - em memória)
    l3_applied_count = apply_layer_3_string_nulling(data)

    # 6. Escrever e Substituir Atomicamente
    if l1_applied_count > 0 or l3_applied_count > 0:
        try:
            print(f"\n[*] Escrevendo DLL modificada...")
            with open(temp_path, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
            print(f"[*] Substituindo atomicamente...")
            os.replace(temp_path, dll_path)
            print("[+] SUCESSO! DLL substituída."); print("[+] SUCESSO! Patches L1 e L3 concluídos."); return True
        except Exception as e: print(f"[X] FALHA CRÍTICA ao gravar DLL: {e}"); return False
        finally:
             if os.path.exists(temp_path):
                  try: os.remove(temp_path)
                  except Exception: pass
    else:
        print("[i] Nenhum patch L1 ou L3 aplicado (DLL já neutralizada)."); return True


def apply_layer_2_block():
    """Aplica o bloqueio no hosts (L2), limpando entradas antigas/duplicadas."""
    print("\n--- [INICIANDO CAMADA 2: BLOQUEIO DE REDE] ---")

    # Marcadores para limpeza (incluindo variações com data/versão)
    ALL_MARKERS_LOWER = [m.lower() for m in OLD_HOSTS_MARKERS_LOWER] + [CURRENT_MARKER_BASE_LOWER]
    DOMAINS_LOWER = [d.lower() for d in DOMAINS_TO_BLOCK]
    new_lines = []; cleaned_hosts = False; original_encoding = 'utf-8'

    try:
        if not os.path.exists(HOSTS_FILE_PATH): print(f"[X] FALHA: Hosts não encontrado."); return False

        # Detecta encoding
        try:
             with open(HOSTS_FILE_PATH, 'rb') as f_rb: raw_data = f_rb.read(1024)
             if raw_data.startswith(b'\xef\xbb\xbf'): original_encoding = 'utf-8-sig'
             elif raw_data.decode('utf-8', errors='strict'): original_encoding = 'utf-8'
        except Exception: original_encoding = sys.getfilesystemencoding() or 'utf-8'

        # 1. Ler e filtrar
        with open(HOSTS_FILE_PATH, 'r', encoding=original_encoding, errors='ignore') as f: all_lines = f.readlines()
        while all_lines and not all_lines[-1].strip(): all_lines.pop()

        for line in all_lines:
            line_strip = line.strip(); line_lower = line_strip.lower()
            
            # Verifica se é uma linha de comentário que contém nosso marcador (qualquer variação)
            if line_strip.startswith('#'):
                is_marker = any(marker in line_lower for marker in ALL_MARKERS_LOWER)
                if is_marker:
                    if not cleaned_hosts: print("[*] Limpando regras antigas/duplicadas...")
                    cleaned_hosts = True; continue
                else: 
                    new_lines.append(line); continue

            # Verifica se é uma regra de domínio nossa
            is_domain_rule = line_strip.startswith('0.0.0.0') and any(domain in line_lower for domain in DOMAINS_LOWER)
            if is_domain_rule:
                if not cleaned_hosts: print("[*] Limpando regras antigas/duplicadas...")
                cleaned_hosts = True; continue

            # Mantém outras linhas
            new_lines.append(line)

        # 2. Adiciona novo bloco (simplificado sem data/versão)
        print("[*] Adicionando regras de bloqueio ao 'hosts'...")
        if new_lines and new_lines[-1].strip(): new_lines.append("\n\n")
        elif not new_lines: pass
        else: new_lines.append("\n")

        # Marcador simplificado
        new_lines.append(f"{HOSTS_BLOCK_MARKER}\n")
        for domain in DOMAINS_TO_BLOCK:
            rule = f"0.0.0.0 {domain}\n"
            new_lines.append(rule)
            print(f"  [+] Regra: {rule.strip()}")
        new_lines.append("\n")

        # 3. Sobrescreve atomicamente
        temp_hosts_path = HOSTS_FILE_PATH + ".fix.tmp"
        try:
            with open(temp_hosts_path, 'w', encoding=original_encoding, errors='ignore', newline='\r\n') as f:
                f.writelines(new_lines); f.flush(); os.fsync(f.fileno())
            os.replace(temp_hosts_path, HOSTS_FILE_PATH)
            print("[+] SUCESSO! Hosts atualizado e limpo.")
        except Exception as write_e: print(f"[X] FALHA ao escrever hosts: {write_e}"); return False
        finally:
             if os.path.exists(temp_hosts_path):
                  try: os.remove(temp_hosts_path)
                  except Exception: pass

        # 4. Flush DNS
        print("[*] Executando 'ipconfig /flushdns'...")
        try:
             startupinfo = subprocess.STARTUPINFO(); startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW; startupinfo.wShowWindow = subprocess.SW_HIDE
             ipconfig_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "ipconfig.exe")
             if not os.path.exists(ipconfig_path): ipconfig_path = 'ipconfig'
             result = subprocess.run([ipconfig_path, '/flushdns'], capture_output=True, text=True, check=True, startupinfo=startupinfo, encoding='cp850', errors='ignore')
             output_lower = result.stdout.lower()
             if "liberado com êxito" in output_lower or "successfully flushed" in output_lower: print("[+] Cache DNS liberado.")
             else: print(f"[!] Aviso flushdns:\n{result.stdout}")
        except Exception as e: print(f"[X] ERRO flushdns: {e}")

        return True

    except Exception as e: print(f"[X] FALHA L2: {e}"); return False


def verify_patches(dll_path):
    """Função de verificação final. Audita as 3 camadas e valida PE."""
    print("\n" + "="*80)
    print("                  RELATÓRIO FINAL DE VERIFICAÇÃO")
    print("="*80)

    camada1_ok = True
    camada2_ok = True
    camada3_ok = True
    pe_valid = True

    # --- Verificação de Integridade PE ---
    print("\n[*] Auditando Integridade da Estrutura PE...")
    try:
        if not os.path.exists(dll_path): raise FileNotFoundError("DLL não encontrada.")
        pe_check = pefile.PE(dll_path)
        _ = pe_check.OPTIONAL_HEADER
        _ = pe_check.FILE_HEADER
        if hasattr(pe_check, 'sections'): _ = [s.Name for s in pe_check.sections]
        pe_check.close()
        print("  [VERIFICADO] Estrutura PE básica válida.")
    except pefile.PEFormatError as pe_err:
        print(f"  [FALHA] Estrutura PE CORROMPIDA: {pe_err}")
        pe_valid = False
        camada1_ok = camada3_ok = False
    except FileNotFoundError as e: print(f"  [FALHA] {e}"); pe_valid = camada1_ok = camada3_ok = False
    except Exception as e:
        print(f"  [FALHA] Erro inesperado ao validar PE: {e}")
        pe_valid = camada1_ok = camada3_ok = False

    # --- Verificação da Camada 1 (IAT) ---
    print("\n[*] Auditando Camada 1 (IAT Patching)...")
    if not pe_valid: print("  [PULADO] Verificação L1 pulada (PE inválido).")
    else:
        try:
            pe = pefile.PE(dll_path)
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']: pointer_size = 4; null_bytes = b'\x00' * 4
            else: pointer_size = 8; null_bytes = b'\x00' * 8

            with open(dll_path, 'rb') as f:
                if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                     print("[!] L1: Tabela IAT não encontrada."); camada1_ok = False
                else:
                     for target_dll, target_function in TARGETS_TO_PATCH_IAT:
                        found = False
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            if entry.dll.lower() == target_dll.lower():
                                for imp in entry.imports:
                                    if imp.name and imp.name.lower() == target_function.lower():
                                        try:
                                            iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                                            file_offset = pe.get_offset_from_rva(iat_rva)
                                            if 0 <= file_offset < os.path.getsize(dll_path) - pointer_size:
                                                f.seek(file_offset); read_bytes = f.read(pointer_size)
                                                if read_bytes == null_bytes: print(f"  [VERIFICADO] L1: '{target_function.decode()}' neutralizada.")
                                                else: print(f"  [FALHA] L1: '{target_function.decode()}' NÃO neutralizada."); camada1_ok = False
                                            else: print(f"  [FALHA] L1: Offset inválido '{target_function.decode()}'."); camada1_ok = False
                                            found = True; break
                                        except Exception as offset_e: print(f"  [FALHA] L1 Erro offset '{target_function.decode()}': {offset_e}"); camada1_ok = False; found = True; break
                                if found: break
                        if not found: print(f"  [FALHA] L1: '{target_function.decode()}' não encontrada."); camada1_ok = False
            pe.close()
        except Exception as e: print(f"  [FALHA] L1 Erro: {e}"); camada1_ok = False

    # --- Verificação da Camada 2 (Hosts) ---
    print("\n[*] Auditando Camada 2 (Arquivo Hosts)...")
    try:
        original_encoding = 'utf-8';
        try:
             with open(HOSTS_FILE_PATH, 'rb') as f_rb: raw_data = f_rb.read(1024)
             if raw_data.startswith(b'\xef\xbb\xbf'): original_encoding = 'utf-8-sig'
             elif raw_data.decode('utf-8', errors='strict'): original_encoding = 'utf-8'
        except Exception: original_encoding = sys.getfilesystemencoding() or 'utf-8'

        with open(HOSTS_FILE_PATH, 'r', encoding=original_encoding, errors='ignore') as f: content = f.read()
        if CURRENT_MARKER_BASE_LOWER not in content.lower():
            print(f"  [FALHA] L2: Marcador '{HOSTS_BLOCK_MARKER}' não encontrado."); camada2_ok = False
        else: print(f"  [VERIFICADO] L2: Marcador de bloqueio encontrado.")

        all_domains_found = True
        for domain in DOMAINS_TO_BLOCK:
            rule_found = False; pattern = re.compile(r"^\s*0\.0\.0\.0\s+" + re.escape(domain) + r"\s*(?:#.*)?$", re.IGNORECASE)
            for line in content.splitlines():
                 if pattern.match(line.strip()): rule_found = True; break
            if not rule_found: print(f"  [FALHA] L2: Regra para '{domain}' não encontrada/inválida."); all_domains_found = False
            else: print(f"  [VERIFICADO] L2: Regra para '{domain}' ativa.")
        if not all_domains_found: camada2_ok = False

    except Exception as e: print(f"  [FALHA] L2: Erro ao ler hosts: {e}"); camada2_ok = False

    # --- Verificação da Camada 3 (String Nulling) ---
    print("\n[*] Auditando Camada 3 (String Nulling)...")
    if not pe_valid: print("  [PULADO] Verificação L3 pulada (PE inválido).")
    else:
        try:
            with open(dll_path, 'rb') as f: data = f.read()
            found_malicious_string = False
            for pattern in STRINGS_TO_NULL:
                for match in pattern.finditer(data):
                    if not all(b == 0x00 for b in match.group(0)):
                         match_str = match.group(0).decode('ascii', errors='ignore')
                         print(f"  [FALHA] L3: String '{match_str}' (offset: {hex(match.start())}) ainda presente!"); camada3_ok = False; found_malicious_string = True
            if not found_malicious_string: print("  [VERIFICADO] L3: Nenhuma string C2/Infra alvo encontrada.")
        except FileNotFoundError: print(f"  [FALHA] L3: DLL não encontrada."); camada3_ok = False
        except Exception as e: print(f"  [FALHA] L3: Erro na verificação: {e}"); camada3_ok = False

    # --- Relatório Final ---
    print("\n" + "-"*80)
    if camada1_ok: print("🟢 STATUS CAMADA 1 (IAT): VERIFICADA.")
    else: print("🔴 STATUS CAMADA 1 (IAT): FALHA.")
    if camada2_ok: print("🟢 STATUS CAMADA 2 (Hosts): VERIFICADA.")
    else: print("🔴 STATUS CAMADA 2 (Hosts): FALHA.")
    if camada3_ok: print("🟢 STATUS CAMADA 3 (Strings): VERIFICADA.")
    else: print("🔴 STATUS CAMADA 3 (Strings): FALHA.")
    if not pe_valid: print("🔴 STATUS PE: FALHA - Estrutura DLL corrompida!")
    print("-" * 80)

    needs_rollback = (pe_valid and (not camada1_ok or not camada3_ok)) or not pe_valid
    return (camada1_ok, camada2_ok, camada3_ok, needs_rollback, pe_valid)

def rollback_from_backup(dll_path):
    """Restaura a DLL original a partir do arquivo .bak."""
    print("\n--- [INICIANDO ROLLBACK AUTOMÁTICO] ---")
    backup_path = dll_path + ".bak"

    if not os.path.exists(backup_path): print(f"[X] FALHA CRÍTICA ROLLBACK: Backup não encontrado."); return False

    try:
        if os.path.exists(dll_path): os.remove(dll_path)
        shutil.copy2(backup_path, dll_path)
        print(f"[+] SUCESSO: DLL revertida do backup."); return True
    except Exception as e: print(f"[X] FALHA CRÍTICA ROLLBACK: {e}"); return False

# --- [4. PONTO DE ENTRADA PRINCIPAL] ---

def main():
    """Orquestra a execução completa do script."""
    print("="*80)
    print("      FIX-STEAMTOOLS: Neutralizador de hid.dll (v0.3.0)")
    print("="*80)

    dll_path = None
    try:
        # 1. Disclaimer e Consentimento
        print_disclaimer_and_get_consent()
        # 2. Aviso Primeira Execução
        print_first_run_warning()
        # 3. Privilégios e Permissões
        check_for_admin_rights()
        # 4. Encerrar Steam
        handle_steam_process()
        # 5. Localizar Steam e DLL
        dll_path = find_steam_and_dll()
        if not dll_path: input("\nPressione Enter para sair."); sys.exit(1)

        # 6. Análise e Relatório
        analysis_report = analyze_and_report(dll_path)
        if analysis_report is None: input("\nPressione Enter para sair."); sys.exit(1)

        # 7. Consentimento Final para Patch
        get_user_consent_to_patch(analysis_report)

        # 8. Aplicar Correções
        l1l3_success = apply_dll_patches(dll_path)
        l2_success = apply_layer_2_block()

        # 9. Verificar e Reportar
        rollback_executed = False
        if l1l3_success or l2_success:
            (camada1_ok, camada2_ok, camada3_ok, needs_rollback, pe_valid) = verify_patches(dll_path)

            if needs_rollback and l1l3_success:
                rollback_executed = rollback_from_backup(dll_path)
                if not rollback_executed: print("\n[X] FALHA CRÍTICA: Rollback não pôde ser concluído!")
                camada1_ok = camada3_ok = not needs_rollback

            if all([camada1_ok, camada2_ok, camada3_ok]) and not rollback_executed:
                print("\n[+] SUCESSO TOTAL! A ameaça foi neutralizada nas 3 camadas.")
            elif rollback_executed:
                 print("\n[!] AVISO: Falha na verificação da DLL. Rollback executado.")
                 print("    A DLL original foi restaurada. Bloqueio de Hosts (L2) pode estar ativo.")
            elif not pe_valid:
                 print("\n[X] FALHA CRÍTICA: Estrutura da DLL corrompida. Rollback falhou ou não aplicável.")
            else:
                 print("\n[X] FALHA NA NEUTRALIZAÇÃO. Verifique os status das camadas.")

        else:
            print("\n[X] Nenhuma ação de correção bem-sucedida.")

        # 10. Recomendação Final
        print("\n" + "="*80)
        print("                 RECOMENDAÇÃO PÓS-PATCH")
        print("="*80)
        print("Para maior segurança, é ALTAMENTE RECOMENDADO que você:")
        print("1. NÃO ABRA MAIS o aplicativo original SteamTools.exe.")
        print("   (Pode substituir a DLL neutralizada).")
        print("2. Utilize métodos alternativos (Manilua, LuaTools via Millenium, etc.)")
        print("   para adicionar novos manifestos.")
        print("="*80)

    except SystemExit: pass
    except KeyboardInterrupt: print("\n[X] Operação interrompida pelo usuário.")
    except Exception as e:
        print("\n" + "="*80)
        print(f"[X] ERRO INESPERADO E CRÍTICO: {e.__class__.__name__}: {e}")
        print("-" * 30 + " Traceback " + "-" * 30)
        print(traceback.format_exc())
        print("-" * (60 + len(" Traceback ")))
        print("    Algo deu muito errado. Reporte este erro no GitHub.")
        print("="*80)
        if dll_path and os.path.exists(dll_path + ".bak"):
             print("\n[*] Tentando rollback devido a erro inesperado...")
             rollback_from_backup(dll_path)

    print("\n[+] Operação concluída.")
    input("Pressione Enter para fechar o programa.")

if __name__ == "__main__":
    main()