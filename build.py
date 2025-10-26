import subprocess
import os
import sys
import shutil

# --- Configuração ---
SOURCE_SCRIPT = "fix-steamtools.py"
OUTPUT_EXE_NAME = "fix-steamtools"
DIST_FOLDER = "dist"
BUILD_FOLDER = "build"

def run_pyinstaller():
    """Tenta executar o PyInstaller para criar o executável."""
    
    # Verifica se o script fonte existe
    if not os.path.exists(SOURCE_SCRIPT):
        print(f"[X] ERRO: O script fonte '{SOURCE_SCRIPT}' não foi encontrado nesta pasta.")
        return False
        
    print(f"[*] Iniciando a compilação de '{SOURCE_SCRIPT}' para '{OUTPUT_EXE_NAME}.exe'...")
    
    # Constrói o comando para o PyInstaller
    command = [
        'pyinstaller',
        '--onefile',      # Cria um único arquivo executável
        '--clean',        # Limpa o cache do PyInstaller antes de construir
        '--name', OUTPUT_EXE_NAME, # Define o nome do .exe
        '--log-level', 'WARN', # Reduz a verbosidade do PyInstaller (opcional)
        SOURCE_SCRIPT     # O script Python a ser compilado
    ]
    
    try:
        print(f"[*] Executando PyInstaller: {' '.join(command)}")
        # Executa o PyInstaller
        # check=True garante que um erro será levantado se o PyInstaller falhar
        # capture_output=True esconde a saída normal do PyInstaller, 
        # mas a captura para exibição em caso de erro. Remova se quiser ver tudo.
        result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        # Se chegou aqui, funcionou
        output_path = os.path.abspath(os.path.join(DIST_FOLDER, f"{OUTPUT_EXE_NAME}.exe"))
        print("\n" + "="*60)
        print(f"[+] SUCESSO! Executável criado em:")
        print(f"    {output_path}")
        print("="*60)
        
        # Limpa a pasta build e o arquivo .spec (opcional)
        cleanup()
        
        return True
        
    except FileNotFoundError:
        print("\n[X] ERRO: Comando 'pyinstaller' não encontrado.")
        print("    Você precisa instalar o PyInstaller primeiro.")
        print("    Execute no seu terminal: pip install pyinstaller")
        return False
        
    except subprocess.CalledProcessError as e:
        print("\n[X] ERRO: O PyInstaller falhou durante a compilação.")
        print("    Saída do PyInstaller:")
        print("-" * 30)
        print(e.stdout)
        print(e.stderr)
        print("-" * 30)
        return False
        
    except Exception as e:
        print(f"\n[X] ERRO INESPERADO durante a compilação: {e}")
        return False

def cleanup():
    """Remove pastas e arquivos temporários do PyInstaller."""
    print("[*] Limpando arquivos temporários...")
    try:
        if os.path.isdir(BUILD_FOLDER):
            shutil.rmtree(BUILD_FOLDER)
            print(f"    - Pasta '{BUILD_FOLDER}' removida.")
        spec_file = f"{OUTPUT_EXE_NAME}.spec"
        if os.path.exists(spec_file):
            os.remove(spec_file)
            print(f"    - Arquivo '{spec_file}' removido.")
    except Exception as e:
        print(f"[!] Aviso: Falha ao limpar arquivos temporários: {e}")


if __name__ == "__main__":
    print("="*60)
    print("      SCRIPT DE BUILD PARA FIX-STEAMTOOLS")
    print("="*60)
    
    # Verifica se o PyInstaller está instalado ANTES de tentar rodar
    # Isso dá uma mensagem de erro mais amigável
    if shutil.which("pyinstaller") is None:
         print("\n[X] ERRO: PyInstaller não encontrado no seu PATH.")
         print("    Por favor, instale-o antes de executar este script de build:")
         print("    pip install pyinstaller")
         sys.exit(1)
         
    run_pyinstaller()
    
    print("\n[+] Processo de build concluído.")
    input("Pressione Enter para fechar.")