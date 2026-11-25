# SecurePeer — alterações de endereços, sincronização e chat

Este pacote contém o código-fonte atualizado. Ele **não contém** `data/`, banco de dados, arquivos de identidade ou chaves privadas. Preserve a sua pasta `data` atual; a inicialização do banco cria as novas tabelas sem apagar peers e registros existentes.

## Arquivos modificados

### `database.py`
- Tabelas `peer_addresses`, `chat_messages` e `identity_nonces`.
- Migração dos endereços antigos de `peers` para `peer_addresses`.
- Inclusão acumulativa de endereços, histórico persistente por peer e deduplicação por IP/porta.

### `security/key_manager.py`
- Descoberta dos IPv4 configurados em todas as interfaces (via `psutil`).
- Atualização local da lista de endereços quando a identidade é selecionada e antes do envio manual.
- Exportação pública inclui somente nome, chaves públicas e endereços. As chaves privadas nunca são incluídas no pacote de sincronização ou no JSON público exportado.

### `network/identity_sync.py` (novo)
- Monta e valida mensagens de sincronização assinadas com Ed25519.
- Confere nome e as duas chaves públicas contra o peer previamente cadastrado.
- Valida endereços e mantém a lista recebida sem substituir os antigos.

### `network/connection_manager.py`
- Botão de sincronização usa os endereços conhecidos em sequência.
- Receptor incorpora todos os endereços anunciados e também o IP observado no socket.
- Responde com a própria identidade pública e lista de endereços.
- Envio de mensagem tenta os endereços em sequência e exige ACK de aplicação assinado pelo peer.

### `network/message_transport.py`
- Protocolo TCP com enquadramento de tamanho e resposta no mesmo socket.

### `core/message_router.py`
- Autenticação antes da verificação de duplicidade.
- Deduplicação por ID de mensagem e integração com histórico de chat.

### `interface/main_window.py`
- Janela principal fica dedicada ao gerenciamento de identidades e peers.
- Botões `Enviar identidade` e `Abrir conversa` ficam abaixo da tabela.
- Duplo clique em um peer também abre sua conversa.

### `interface/chat_window.py` (novo)
- Janela independente por peer, com histórico persistente e envio de mensagens.
- Fechar a janela não apaga o histórico nem remove o peer.

### `interface/identity_window.py`
- Exibe os endereços locais anunciados na identidade pública.

### `requirements.txt`
- Adiciona `psutil` para enumerar endereços IPv4 de todas as interfaces de rede.

## Instalação

1. Feche o SecurePeer.
2. Faça uma cópia de segurança da pasta inteira do projeto, especialmente `data/`.
3. Extraia este pacote em uma pasta temporária.
4. Copie os arquivos e pastas do pacote por cima do projeto, mantendo a pasta `data/` que já existe. Não substitua nem apague `data/identities/` ou `data/securepeer.db`.
5. No ambiente virtual do projeto, execute:

   ```powershell
   python -m pip install -r requirements.txt
   ```

6. Inicie com `python main.py`.

O banco será migrado ao abrir o programa. A primeira inicialização pode criar as novas tabelas e migrar o IP atualmente cadastrado para a lista de endereços.

## Como usar

1. Em cada computador, abra o SecurePeer e selecione a identidade local. O programa atualiza localmente os IPv4 encontrados nas interfaces, sem iniciar handshake ou transmitir identidade automaticamente.
2. Inicie o receptor nas duas máquinas (TCP 8765 liberado no firewall).
3. Selecione o peer e clique em **Enviar identidade**. Esse é o único momento em que ocorre a sincronização manual: cada lado envia a identidade pública assinada e responde com sua própria identidade/lista de endereços.
4. Para conversar, selecione o peer e clique em **Abrir conversa**. Cada peer tem uma janela e um histórico persistente.

## Limitações importantes

- A descoberta registra endereços locais das interfaces, não descobre automaticamente o IP público do roteador. IP privado anunciado pode não ser alcançável fora daquela rede.
- Ainda não há NAT traversal, túnel ou relay. A sincronização acumula endereços para tentativas futuras, mas não cria conectividade entre redes isoladas ou sob CGNAT.
- A porta de serviço anunciada é a porta TCP configurada (`8765`).
- O arquivo de identidade local continua contendo chaves privadas sem criptografia em repouso, como no projeto original. Nunca compartilhe a pasta `data/` nem envie esses arquivos ao GitHub.
- A sincronização exige que o peer já esteja cadastrado e marcado como confiável. O pacote não substitui a verificação independente das fingerprints.

## Verificações realizadas

- Compilação sintática de todos os módulos Python (`compileall`).
- Importação dos módulos modificados.
- Teste de banco: criação das tabelas, endereços, deduplicação e histórico.
- Teste de integração local: recepção de sincronização assinada, resposta assinada, mensagem criptografada e ACK autenticado.


## Correção adicional — janela de chat e validação do destinatário

- A janela de chat agora exibe o botão **Enviar mensagem** em uma faixa própria, abaixo do campo de texto.
- `Enter` envia a mensagem; `Shift+Enter` cria uma nova linha; `Ctrl+Enter` também envia.
- A validação de assinatura Ed25519 acontece antes de confiar nos campos de identidade do pacote.
- Se o destinatário não corresponder à identidade local ativa, o DEBUG agora informa o nome recebido e o nome esperado, sem desativar a autenticação.
- Ao cadastrar um peer, informe como nome exatamente o nome da identidade criada na outra máquina. O nome não é um apelido livre: ele é usado no vínculo criptográfico do protocolo.

Se o DEBUG indicar `Destinatário incompatível`, confira a identidade selecionada na janela principal de quem está recebendo e compare-a com o nome de identidade que aparece no pacote/erro. Não corrija isso removendo a verificação: ajuste o cadastro/identidade para que os nomes correspondam.
