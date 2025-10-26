# FIX-STEAMTOOLS: Neutralizador de hid.dll

Script em Python (v0.2.0) projetado para analisar e neutralizar componentes potencialmente maliciosos encontrados na `hid.dll` modificada por ferramentas como a "SteamTools", sem quebrar sua funcionalidade principal (carregamento de manifestos).

[![Licença](https://img.shields.io/badge/Licença-MIT-blue)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/lucaswotta/fix-steamtools)](https://github.com/lucaswotta/fix-steamtools/stargazers)

---

## Contexto

Softwares que modificam ou adicionam uma `hid.dll` na pasta de instalação da Steam revelam a inclusão de funcionalidades não nativas de uma `hid.dll` padrão, como capacidades de rede e comunicação com domínios externos específicos.

## O Risco Potencial

Embora a intenção principal possa ser funcional (ex: atualizações), a presença dessas funcionalidades extras introduz riscos de segurança:

1.  **Capacidade de Backdoor:** Funções para *receber* conexões de rede (`accept`, `listen`, `bind`) estão presentes, abrindo a *possibilidade* de acesso remoto não autorizado.
2.  **Comunicação Externa:** A DLL contém referências (strings) a domínios específicos e capacidade de *iniciar* conexões, o que poderia ser usado para exfiltração de dados.

## A Solução: Neutralização em 3 Camadas

O `fix-steamtools` aplica correções técnicas para mitigar esses riscos específicos, preservando a funcionalidade da DLL:

* **CAMADA 1 (IAT Patching):** Neutraliza as funções de *recebimento* de conexão (`accept`, `listen`, `bind`) na Tabela de Importação da DLL, desativando o potencial backdoor passivo.
* **CAMADA 2 (Bloqueio de Rede):** Bloqueia a comunicação *de saída* para os domínios C2 conhecidos, adicionando regras ao arquivo `hosts` do Windows.
* **CAMADA 3 (String Nulling):** Localiza e sobrescreve (com zeros) as strings dos domínios C2 *dentro* do arquivo da DLL, como uma segunda linha de defesa contra a comunicação externa.

## Recursos Principais

* **Análise Detalhada:** Verifica importações, strings suspeitas e assinatura digital, gerando um relatório (`.txt`).
* **Neutralização Tripla:** Aplica as três camadas de correção descritas acima.
* **Detecção Automática:** Localiza a instalação da Steam e a DLL alvo (`hid.dll`, `hid64.dll`, etc.).
* **Segurança:** Cria backup (`.bak`), aplica patches de forma atômica (evita corrupção) e realiza rollback automático se a verificação pós-patch falhar.
* **Automação:** Verifica se a Steam está aberta e oferece para fechá-la; instala dependências Python (`pefile`, `psutil`) automaticamente se necessário.
* **Limpeza:** Remove entradas duplicadas/antigas do `hosts` criadas por versões anteriores do script.

## Como Usar

1.  **Baixe o Executável:**
    * Vá para a seção **["Releases"](https://github.com/lucaswotta/fix-steamtools/releases)**.
    * Baixe o `fix-steamtools.exe` da versão mais recente (em "Assets").
    * *(Alternativa para devs: Baixe o `fix-steamtools.py` e execute com Python 3)*.
2.  **Feche a Steam:** Certifique-se de que a Steam esteja **completamente fechada**.
3.  **Execute como Administrador:** Clique com o botão direito no `fix-steamtools.exe` e selecione **"Executar como administrador"**.
4.  **Aceite o Aviso Legal:** Leia os termos. Se concordar, digite `EU CONCORDO` e pressione Enter.
5.  **Confirme a Ação:** Revise o relatório de análise e o plano de neutralização. Pressione Enter para iniciar.
6.  **Aguarde:** O script aplicará as 3 camadas e verificará o resultado.
7.  **Concluído:** Verifique a mensagem final de sucesso ou falha. Pressione Enter para fechar. Agora você pode abrir a Steam.

## ⚠️ Aviso de Antivírus (Falso Positivo)

Seu antivírus (Windows Defender, etc.) **provavelmente sinalizará** o `fix-steamtools.exe` (ou `.py`).

**Isto é um falso positivo esperado.** A ferramenta é detectada porque suas ações *legítimas* são semelhantes às de malware:
* Modifica o arquivo `hosts` (para bloquear C2s).
* Modifica um arquivo `.dll` (para aplicar patches de segurança).

O código-fonte está aqui aberto para auditoria. Adicione uma exceção no seu antivírus se necessário.

## Disclaimer (Aviso Legal)

Este script é para fins educacionais e de segurança. O autor não se responsabiliza por danos, perdas ou banimentos. **Use por sua conta e risco.** A `hid.dll` modificada ainda é de fonte não confiável; este script apenas mitiga os riscos *conhecidos*.

## Licença

MIT License - Copyright (c) 2025 Lucas Motta.
