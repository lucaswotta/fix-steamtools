# FIX-STEAMTOOLS: Neutralizador de hid.dll

Script em Python projetado para neutralizar os componentes maliciosos da `hid.dll` modificada pelo SteamTools, sem quebrar sua funcionalidade principal.

## O Problema

A `hid.dll` fornecida pela "SteamTools" não é limpa. Ela contém código malicioso injetado que, embora permita o carregamento de manifestos de jogos, também abre riscos de segurança graves, incluindo:

* **Backdoor Passivo:** A DLL "ouve" por conexões de rede de entrada, permitindo que um invasor se conecte ao seu PC.
* **Exfiltração de Dados:** A DLL tenta comunicar para domínios estranhos, abrindo um canal para enviar seus dados.

## A Solução (Dupla Camada)

Este script atua para neutralizar a ameaça sem quebrar a funcionalidade que você deseja.

* **CAMADA 1 (CIRURGIA NA DLL):** Desativa o backdoor passivo. O script aplica um "patch" na Tabela de Importação (IAT) da DLL, sobrescrevendo as funções `accept`, `listen`, e `bind` com bytes nulos.
* **CAMADA 2 (BLOQUEIO DE REDE):** Desativa a exfiltração de dados. O script adiciona regras ao seu arquivo `hosts` do Windows para redirecionar os domínios maliciosos conhecidos para um "buraco negro" (`0.0.0.0`).

## Recursos

* **Auto-Instalação:** Instala automaticamente as dependências `pefile` e `psutil` se não as encontrar.
* **Detecção Automática:** Localiza sua instalação da Steam automaticamente via Registro do Windows.
* **Análise e Relatório:** Gera um `.txt` com as ameaças encontradas na DLL.
* **Segurança (Rollback):** Cria um backup (`.bak`) e, se a verificação pós-patch falhar, restaura o backup automaticamente para não corromper sua Steam.

## Como Usar

1.  Baixe o arquivo `fix-steamtools.py` deste repositório.
2.  Certifique-se de que a Steam esteja **completamente fechada**.
3.  Clique com o botão direito no `fix-steamtools.py` e selecione **"Executar como administrador"**.
4.  Leia o aviso legal e, se concordar, digite `EU CONCORDO` e pressione Enter.
5.  O script fará a análise, pedirá sua confirmação final e aplicará as correções.
6.  Após a conclusão, você pode abrir a Steam com segurança.


## Aviso de Antivírus (Falso Positivo)

**O seu antivírus (Windows Defender, etc.) MUITO PROVAVELMENTE sinalizará este script.**

Isso é um **falso positivo esperado**. O script é sinalizado porque seu *comportamento* é inerentemente suspeito para um antivírus:

1.  **Modifica o arquivo `hosts`:** Esta é uma tática comum de malware para bloquear atualizações ou redirecionar tráfego. (Nós fazemos isso para bloquear os servidores do malware).
2.  **Modifica um arquivo `.dll`:** Fazer "patch" em binários é um comportamento clássico de "patchers" ou "cracks". (Nós fazemos isso para "aleijar" o backdoor).

Você pode (e deve!) ler o código-fonte completo (`fix-steamtools.py`) para verificar que ele faz apenas o que está descrito.

## Disclaimer (Aviso Legal)

Este script é fornecido estritamente para fins educacionais e de segurança defensiva. O autor não se responsabiliza por quaisquer danos, perdas ou banimentos de conta decorrentes do uso deste software. **Use por sua inteira conta e risco.**

A DLL alvo ainda é de uma fonte não confiável. Este script apenas tenta neutralizar as ameaças conhecidas.

## Licença

Este projeto é licenciado sob a Licença MIT. 

Copyright (c) 2025 Lucas Motta