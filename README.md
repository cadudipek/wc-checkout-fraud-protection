# WooCommerce IP Blocker

Sistema de bloqueio de IPs no checkout WooCommerce para prevenção de fraudes.

## Funcionalidades
- Limita tentativas de checkout por IP (5 tentativas / 1 hora)
- Mantém log de bloqueios
- Permite desbloqueio manual via WP Admin

## Instalação
1. Copie `ip-blocker.php` para o seu plugin ou adicione via Code Snippets
2. Ative o snippet

## Teste
- Realize 5 checkouts pelo mesmo IP
- Na 6ª tentativa, o checkout será bloqueado
- Verifique logs em **Ferramentas → IP Block Logs**

## Desbloqueio
- WP Admin → Ferramentas → IP Block Logs
- Selecione IP e clique em desbloquear
