<?php
// ============================================
// Bloqueio de IP no Checkout WooCommerce
// ============================================

// Limita tentativas de checkout por IP para evitar fraudes
if ( ! defined( 'ABSPATH' ) ) {
    exit; // evita acesso direto
}

// Configurações básicas
add_action( 'init', function() {
    if ( ! defined( 'IP_BLOCK_MAX_ATTEMPTS' ) ) define( 'IP_BLOCK_MAX_ATTEMPTS', 5 );        // tentativas máximas
    if ( ! defined( 'IP_BLOCK_WINDOW_SECONDS' ) ) define( 'IP_BLOCK_WINDOW_SECONDS', 3600 ); // 1 hora
    if ( ! defined( 'IP_BLOCK_LOG_OPTION' ) ) define( 'IP_BLOCK_LOG_OPTION', 'ip_block_logs' );
});

// Função para capturar IP real, incluindo Cloudflare ou proxies
function ip_block_get_ip() {
    if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
        return sanitize_text_field( $_SERVER['HTTP_CF_CONNECTING_IP'] );
    }
    if ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
        $ips = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
        return sanitize_text_field( trim( $ips[0] ) );
    }
    return isset( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( $_SERVER['REMOTE_ADDR'] ) : '0.0.0.0';
}

// Incrementa contador de tentativas
function ip_block_increment_attempts( $ip ) {
    $key = 'ip_block_count_' . md5( $ip );
    $count = (int) get_transient( $key );
    $count++;
    set_transient( $key, $count, IP_BLOCK_WINDOW_SECONDS );
    return $count;
}

// Retorna número atual de tentativas
function ip_block_get_attempts( $ip ) {
    $key = 'ip_block_count_' . md5( $ip );
    return (int) get_transient( $key );
}

// Salva log de bloqueio
function ip_block_log_blocked_attempt( $ip, $details = array() ) {
    $log_option = get_option( IP_BLOCK_LOG_OPTION, array() );
    if ( ! is_array( $log_option ) ) $log_option = array();

    $entry = array(
        'time'       => current_time( 'mysql' ),
        'timestamp'  => time(),
        'ip'         => $ip,
        'attempts'   => isset( $details['attempts'] ) ? intval( $details['attempts'] ) : ip_block_get_attempts( $ip ),
        'user_agent' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? wp_trim_words( $_SERVER['HTTP_USER_AGENT'], 20 ) : '',
        'email'      => isset( $details['email'] ) ? sanitize_email( $details['email'] ) : '',
        'url'        => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
    );

    array_unshift( $log_option, $entry );
    if ( count( $log_option ) > 500 ) $log_option = array_slice( $log_option, 0, 500 );
    update_option( IP_BLOCK_LOG_OPTION, $log_option );
}

// Checagem de bloqueio no checkout
add_action( 'woocommerce_checkout_process', 'ip_block_check_on_checkout' );

function ip_block_check_on_checkout() {
    $ip = ip_block_get_ip();
    $current = ip_block_get_attempts( $ip );

    if ( $current >= IP_BLOCK_MAX_ATTEMPTS ) {
        $details = array(
            'attempts' => $current,
            'email'    => isset( $_POST['billing_email'] ) ? sanitize_email( $_POST['billing_email'] ) : '',
        );
        ip_block_log_blocked_attempt( $ip, $details );

        wc_add_notice(
            sprintf(
                'Detectamos várias tentativas de pagamento a partir do seu IP (%s). Por segurança, novas tentativas estão bloqueadas por %d minutos.',
                esc_html( $ip ),
                intval( IP_BLOCK_WINDOW_SECONDS / 60 )
            ),
            'error'
        );
        return;
    }

    $new = ip_block_increment_attempts( $ip );
    if ( $new === IP_BLOCK_MAX_ATTEMPTS ) {
        ip_block_log_blocked_attempt( $ip, array(
            'attempts' => $new,
            'email'    => isset( $_POST['billing_email'] ) ? sanitize_email( $_POST['billing_email'] ) : '',
        ) );
    }
}

// ============================================
// Funções de desbloqueio manual
// ============================================
function ip_block_unblock_ip( $ip ) {
    delete_transient( 'ip_block_count_' . md5( $ip ) );
}

function ip_block_remove_logs_for_ip( $ip ) {
    $logs = get_option( IP_BLOCK_LOG_OPTION, array() );
    if ( ! is_array( $logs ) ) return;
    $new = array_filter( $logs, fn( $row ) => $row['ip'] !== $ip );
    update_option( IP_BLOCK_LOG_OPTION, array_values( $new ) );
}

function ip_block_remove_log_index( $index ) {
    $logs = get_option( IP_BLOCK_LOG_OPTION, array() );
    if ( isset( $logs[ $index ] ) ) {
        unset( $logs[ $index ] );
        update_option( IP_BLOCK_LOG_OPTION, array_values( $logs ) );
    }
}

add_action( 'admin_init', function() {
    if ( ! current_user_can( 'manage_options' ) ) return;

    if ( isset( $_POST['ip_block_action'] ) && $_POST['ip_block_action'] === 'unblock_ip' ) {
        check_admin_referer( 'ip_block_unblock_action', 'ip_block_nonce' );
        $ip = sanitize_text_field( $_POST['ip'] ?? '' );
        ip_block_unblock_ip( $ip );
        if ( isset( $_POST['ip_block_remove_logs'] ) && $_POST['ip_block_remove_logs'] === '1' ) {
            ip_block_remove_logs_for_ip( $ip );
        }
        add_action( 'admin_notices', fn() => print '<div class="updated"><p>IP desbloqueado.</p></div>' );
    }

    if ( isset( $_POST['ip_block_action'] ) && $_POST['ip_block_action'] === 'remove_log_entry' ) {
        check_admin_referer( 'ip_block_remove_log', 'ip_block_nonce' );
        $index = intval( $_POST['log_index'] ?? -1 );
        ip_block_remove_log_index( $index );
        add_action( '
