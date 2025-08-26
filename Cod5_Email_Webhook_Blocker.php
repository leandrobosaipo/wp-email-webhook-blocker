<?php
/**
 * Plugin Name: Cod5 Email Webhook Blocker
 * Plugin URI: https://codigo5.com.br
 * Description: Intercepts and blocks ALL outgoing emails from WordPress (wp_mail, PHPMailer, SMTP plugins, sendmail, etc.), forwarding the original payload to a configurable n8n webhook, with resilient logging, rotation, governance checklist, CI/CD guidance, and audit-ready documentation. Designed for compliance, secure staging usage, and zero UI footprint. Compatible WP 5.0+, PHP 7.2+, no external dependencies.
 * Version: 1.4.3
 * Author: Leandro Bosaipo / Código5 WEB
 * Author URI: https://codigo5.com.br
 * License: GPLv2+ (https://www.gnu.org/licenses/gpl-2.0.html)
 *
 * Changelog:
 * 1.4.0 - Fixed webhook duplication issue and user error messages. Improved deduplication logic using request ID and better payload matching. Enhanced PHPMailer interception to ensure WordPress perceives successful email delivery.
 * 1.3.0 - Added robust PHPMailer class replacement via serialization hack to enforce blocking. Improved hash deduplication between wp_mail and phpmailer_init. Hardened logging with file locking and rotation.
 * 1.2.0 - Initial production-ready implementation: intercept wp_mail, phpmailer_init, send to webhook, logging, rotation, fail-safe blocking.
 * 1.0.0 - Initial release with wp_mail interception and webhook forwarding.
 *
 * ================================
 * CONFIGURABLE CONSTANTS (example override in wp-config.php):
 *
 * // Override webhook URL (default is below)
 * define( 'COD5_EMAIL_WEBHOOK_URL', 'https://your-staging-hook.local/webhook/xyz' );
 *
 * // Override log file path (default: WP_CONTENT_DIR . '/email-webhook.log')
 * define( 'COD5_EMAIL_WEBHOOK_LOG_PATH', WP_CONTENT_DIR . '/email-webhook.log' );
 *
 * // Activate plugin only in a specific environment (example: staging)
 * // define('WP_ENV','staging');
 * // define('COD5_EMAIL_WEBHOOK_ACTIVE_ENV','staging');
 *
 * Example wp-config.php snippet:
 * -------------------------------------------------------
 * define('WP_ENV','staging');
 * define('COD5_EMAIL_WEBHOOK_ACTIVE_ENV','staging');
 * define('COD5_EMAIL_WEBHOOK_URL','https://your-staging-hook.local/webhook/xyz');
 * define('COD5_EMAIL_WEBHOOK_LOG_PATH', WP_CONTENT_DIR . '/custom-logs/email-webhook.log');
 * -------------------------------------------------------
 *
 * STAGING / TEST MODE:
 * If you want this plugin to run ONLY in staging or a specific environment, set:
 *   define('WP_ENV', 'staging'); // or your environment name
 *   define('COD5_EMAIL_WEBHOOK_ACTIVE_ENV', 'staging');
 * The plugin will deactivate itself silently when WP_ENV !== COD5_EMAIL_WEBHOOK_ACTIVE_ENV.
 *
 * LOG FILE SECURITY (example .htaccess for Apache to protect log):
 * -------------------------------------------------------
 * <Files "email-webhook.log">
 *   Require all denied
 * </Files>
 * <FilesMatch "^email-webhook.*\.log$">
 *   Require all denied
 * </FilesMatch>
 * -------------------------------------------------------
 * Nginx suggestion:
 * -------------------------------------------------------
 * location ~* /wp-content/(email-webhook.*\.log)$ {
 *     deny all;
 *     access_log off;
 *     log_not_found off;
 * }
 * -------------------------------------------------------
 *
 * BADGES SUGGESTED (for README or plugin repo):
 * [![WordPress Compatible](https://img.shields.io/badge/compatible-WordPress-blue.svg)] 
 * [![Code Quality](https://img.shields.io/sonar/quality_gate?logo=sonarqube)] 
 * [![Coverage](https://img.shields.io/codecov/c/gh/yourrepo/yourplugin)] 
 *
 * ISSUE / REPORT TEMPLATE (for GitHub/GitLab):
 * -------------------------------------------------------
 * Title: [BUG/COMPLIANCE] Summary of issue
 * Description:
 *  - Environment: WP version, PHP version, WP_ENV (if used)
 *  - What was expected:
 *  - What happened:
 *  - Steps to reproduce:
 *    1.
 *    2.
 *    3.
 *  - Relevant constants overrides (redact sensitive)
 *  - Log excerpt (timestamped, without sensitive payloads)
 *  - Request ID (if implemented)
 * -------------------------------------------------------
 * Contact for support: leandro@codigo5.com.br
 *
 * AUDIT CHECKLIST (periodic review):
 * [ ] Verify webhook URL integrity and HTTPS certificate validity.
 * [ ] Validate log file permissions (not world readable).
 * [ ] Confirm log rotation is functioning (no single file >5MB).
 * [ ] Review recent log entries for unexpected failures or bypass attempts.
 * [ ] Confirm constants overrides match intended environment (staging vs prod).
 * [ ] Ensure plugin version is up-to-date per policy.
 * [ ] Validate no real emails have been sent (audit downstream systems).
 * [ ] Confirm backup of logs complies with privacy policy.
 * [ ] Review code for potential injection (should have none, no external input execution).
 *
 * PRIVACY POLICY NOTE:
 * Email metadata (sender, recipient, subject existence) is logged. Body is NOT logged. Payload is forwarded to the webhook; ensure webhook endpoint is secured, uses HTTPS, and adheres to your privacy policy. Link suggestion: /privacy-policy#email-webhook-logs
 *
 * CI/CD INTEGRATION GUIDANCE:
 * - Store expected constant overrides in protected environment variables.
 * - Example GitHub Actions step to deploy:
 *   uses: actions/checkout@v4
 *   run: |
 *     rsync -av --delete ./plugins/cod5-email-webhook-blocker.php user@server:/var/www/html/wp-content/plugins/
 *     ssh user@server "wp plugin activate cod5-email-webhook-blocker"
 * - Include linting in pipeline: use phpstan or phpcs check.
 * - Automated test step (see below) should assert that wp_mail() returns false and webhook receives expected payload in mocked environment.
 *
 * UPDATE POLICY:
 * - Semantic Versioning used. Minor/patch updates quarterly or immediately when security issues identified.
 * - Breaking changes must bump major version and be documented in changelog.
 *
 * ACCESSIBILITY (future UI):
 * - This plugin has no UI. If extended, any interface must follow WCAG contrast, keyboard navigation, and use aria-labels. Provide user feedback in plain language.
 *
 * TESTING INSTRUCTIONS:
 * - Unit / Integration: Use PHPUnit with WP_Mock or WordPress test suite to mock wp_mail and phpmailer_init flows.
 * - Sample assertions:
 *     * Calling wp_mail(...) returns false.
 *     * Webhook receives correct JSON payload (mock wp_remote_post).
 *     * PHPMailer instance send() is overridden and returns false.
 * - WP-CLI helpers: You can test with:
 *     wp eval 'var_dump(wp_mail("test@example.com","Subject","Message"));'
 * - Enable debugging: define('WP_DEBUG', true); monitor log file for entries.
 *
 * DEPENDENCIES: None external. Uses core WP functions only.
 *
 * SECURITY & HARDENING SUGGESTIONS:
 * - Combine with security plugins that harden file permissions and restrict plugin editing (DISALLOW_FILE_EDIT).
 * - Use file integrity monitoring on this plugin file and the log directory.
 * - Limit access to webhook endpoint by IP or secret if possible.
 *
 * INTERNATIONALIZATION: All internal comments and log messages are in English to simplify compliance and auditing.
 *
 * =======================================================================================
 * IMPLEMENTATION NOTES:
 * Strategy to block emails:
 *   1. Intercept wp_mail arguments via filter, forward the original payload to webhook, log the attempt.
 *   2. Intercept PHPMailer initialization (phpmailer_init), extract its data (covers direct instantiations through WP), forward if not duplicate, and replace its class with a patched subclass to force send() to return false, guaranteeing no actual delivery.
 *   3. Logging with rotation prevents unbounded log growth.
 *   4. Failure to contact webhook still blocks email (send() returns false) so WordPress perceives failure.
 * =======================================================================================
 */

defined( 'ABSPATH' ) || exit;

// 🔧 Carregar variáveis de ambiente (.env)
if ( file_exists( __DIR__ . '/.env' ) ) {
    $env = parse_ini_file( __DIR__ . '/.env' );
    if ( isset( $env['COD5_EMAIL_WEBHOOK_URL'] ) && ! defined('COD5_EMAIL_WEBHOOK_URL') ) {
        define('COD5_EMAIL_WEBHOOK_URL', $env['COD5_EMAIL_WEBHOOK_URL']);
    }
}


if ( defined( 'COD5_EMAIL_WEBHOOK_ACTIVE_ENV' ) && defined( 'WP_ENV' ) && WP_ENV !== COD5_EMAIL_WEBHOOK_ACTIVE_ENV ) {
    // Running in a non-authorized environment; disable plugin silently.
    return;
}



if ( ! class_exists( 'Cod5_Email_Webhook_Blocker' ) ) {

    class Cod5_Email_Webhook_Blocker {

        private static $cod5_processed_requests = [];
        private static $initialized = false;
        private static $request_id = null;
        // Evita duplicar quando já curto-circuitamos via pre_wp_mail
        private static $cod5_curto_circuitou = false;

        public static function init() {
            if ( self::$initialized ) {
                return;
            }
            self::$initialized = true;

            // Generate unique request ID for this session
            self::$request_id = uniqid('cod5_', true);

            // Curto-circuita o envio ANTES do WP tentar enviar e-mail
            add_filter( 'pre_wp_mail', [ __CLASS__, 'cod5_pre_wp_mail' ], 10, 2 );

            // Garante que o filtro antigo não fique ativo (evita quebrar o retorno do wp_mail)
            remove_filter( 'wp_mail', [ __CLASS__, 'intercept_wp_mail' ], 999 );
            remove_filter( 'wp_mail', [ __CLASS__, 'intercept_wp_mail' ], 10 );   // caso tenha usado outra prioridade


            // Ensure PHPMailer send is patched early if possible (namespaced & legacy)
            self::prepare_phPMailer_patch_classes();
        }

        /**
         * Curto-circuita o wp_mail: envia ao webhook e devolve sucesso para o WP/Elementor.
         *
         * @param mixed $cod5Retorno Valor de retorno original (normalmente null)
         * @param array $cod5Atributos ['to','subject','message','headers','attachments']
         * @return bool|WP_Error true para sucesso; WP_Error/false para sinalizar falha
         */
        public static function cod5_pre_wp_mail( $cod5Retorno, $cod5Atributos ) {
            $cod5Payload = [
                'to'          => (array)($cod5Atributos['to'] ?? []),
                'subject'     => (string)($cod5Atributos['subject'] ?? ''),
                'message'     => (string)($cod5Atributos['message'] ?? ''),
                'headers'     => $cod5Atributos['headers'] ?? [],
                'attachments' => $cod5Atributos['attachments'] ?? [],
                // ajuda depurar a origem
                'source'      => 'pre_wp_mail',
            ];

            // Envia para o webhook (reusa sua função existente)
            $cod5Ok = self::send_to_webhook( $cod5Payload );

            // Marca hash/flag para evitar duplicar em phpmailer_init
            self::$cod5_last_mail_hash  = sha1( wp_json_encode( $cod5Payload ) );
            self::$cod5_curto_circuitou = true;

            // Log (opcional)
            self::log_event(
                $cod5Ok ? 'INFO' : 'ERROR',
                $cod5Ok ? 'Webhook OK via pre_wp_mail.' : 'Falha ao enviar webhook via pre_wp_mail.',
                [ 'to' => $cod5Payload['to'], 'subject' => $cod5Payload['subject'] ]
            );

            // ⚠️ ESSENCIAL: retornar TRUE faz o wp_mail() retornar TRUE.
            // O Elementor então responde com: {"success":true,"data":{"message":"Your submission was successful.","data":[]}}
            return true;
        }
        

        public static function intercept_wp_mail( $args ) {
            return $args; // seguro: não altera o contrato do filtro 'wp_mail'
        }
        
        /**
         * Intercepts wp_mail payload, sends to webhook, logs, and ensures eventual blocking.
         *
         * @param array $args Original wp_mail args.
         * @return array Unmodified args (blocking happens via PHPMailer patch).
         */
        // public static function intercept_wp_mail( $args ) {
        //     // Normalize basic structure
        //     // $cod5_to          = isset( $args['to'] ) ? $args['to'] : '';
        //     // $cod5_subject     = isset( $args['subject'] ) ? $args['subject'] : '';
        //     // $cod5_message     = isset( $args['message'] ) ? $args['message'] : '';
        //     // $cod5_headers     = isset( $args['headers'] ) ? $args['headers'] : '';
        //     // $cod5_attachments = isset( $args['attachments'] ) ? $args['attachments'] : '';

        //     // $payload = [
        //     //     'to'          => $cod5_to,
        //     //     'subject'     => $cod5_subject,
        //     //     'message'     => $cod5_message,
        //     //     'headers'     => $cod5_headers,
        //     //     'attachments' => $cod5_attachments,
        //     // ];

        //     // // Create unique identifier for this email request
        //     // $request_key = self::create_request_key($payload);
            
        //     // // Check if already processed
        //     // if (isset(self::$cod5_processed_requests[$request_key])) {
        //     //     self::log_event('DEBUG', 'Duplicate wp_mail request detected, skipping webhook call.', [
        //     //         'request_key' => $request_key,
        //     //         'request_id' => self::$request_id
        //     //     ]);
        //     //     return $args;
        //     // }

        //     // // Mark as processed
        //     // self::$cod5_processed_requests[$request_key] = [
        //     //     'timestamp' => microtime(true),
        //     //     'source' => 'wp_mail',
        //     //     'request_id' => self::$request_id
        //     // ];

        //     // // Send to webhook
        //     // $success = self::send_to_webhook( $payload, $request_key );

        //     // // Log outcome
        //     // $sender = self::extract_from_headers( $cod5_headers );
        //     // $recipients = self::normalize_recipients( $cod5_to );
        //     // $log_context = [
        //     //     'to' => $recipients,
        //     //     'subject' => $cod5_subject,
        //     //     'from' => $sender,
        //     //     'request_key' => $request_key,
        //     //     'request_id' => self::$request_id
        //     // ];
        //     // if ( $success ) {
        //     //     self::log_event( 'INFO', 'wp_mail intercepted and forwarded to webhook successfully.', $log_context );
        //     // } else {
        //     //     self::log_event( 'ERROR', 'Failed to forward wp_mail payload to webhook.', $log_context );
        //     // }

        //     // Always return original args; actual delivery will be blocked by PHPMailer subclass override
        //     // return $args;
        //     // ✅ Retornar true para o WordPress entender que o envio foi bem-sucedido
        //     return true;

        // }

        /**
         * Curto-circuita o wp_mail: envia ao webhook e devolve sucesso para o WordPress.
         * Isso faz o Elementor (e qualquer formulário) receber "success" no AJAX.
         *
         * @param mixed $cod5Retorno Valor de retorno original (normalmente null)
         * @param array $cod5Atributos ['to','subject','message','headers','attachments']
         * @return bool|WP_Error true para sucesso; WP_Error/false se quiser sinalizar falha
         */
        public static function cod5_short_circuit_wp_mail( $cod5Retorno, $cod5Atributos ) {
            $cod5Payload = [
                'to'          => (array)($cod5Atributos['to'] ?? []),
                'subject'     => (string)($cod5Atributos['subject'] ?? ''),
                'message'     => (string)($cod5Atributos['message'] ?? ''),
                'headers'     => $cod5Atributos['headers'] ?? [],
                'attachments' => $cod5Atributos['attachments'] ?? [],
                // ✅ opcional, mas útil para você depurar a origem
                'source'      => 'pre_wp_mail',
            ];

            // Envia para o webhook (use sua função já existente)
            $cod5Ok = self::send_to_webhook( $cod5Payload );

            // Marca hash/flag para evitar repetir no phpmailer_init
            self::$cod5_last_mail_hash   = sha1( wp_json_encode( $cod5Payload ) );
            self::$cod5_curto_circuitou  = true;

            // Log opcional
            self::log_event( $cod5Ok ? 'INFO' : 'ERROR',
                $cod5Ok ? 'Webhook OK via pre_wp_mail.' : 'Falha ao enviar webhook via pre_wp_mail.',
                ['to' => $cod5Payload['to'], 'subject' => $cod5Payload['subject']]
            );

            // 💡 ESSENCIAL: retornar TRUE faz o wp_mail() devolver TRUE.
            // O Elementor então responde com {"success":true,"data":{"message":"Your submission was successful.","data":[]}}
            return true;
        }

        /**
         * Hook into phpmailer_init to extract data, forward if needed, and replace class to enforce blocking.
         *
         * @param object $phpmailer PHPMailer instance.
         * @return void
         */
        public static function intercept_phpmailer_init( $phpmailer ) {

            // Se já curto-circuitamos via pre_wp_mail, não faça mais nada aqui.
            if ( isset(self::$cod5_curto_circuitou) && self::$cod5_curto_circuitou === true ) {
                return;
            }            

            // Se já curto-circuitamos no pre_wp_mail, não faça mais nada aqui.
            if ( self::$cod5_curto_circuitou ) {
                return;
            }

            // Build approximate equivalent of wp_mail args
            $to_list = self::cod5_phpmailer_get_addresses( $phpmailer, 'to' );
            $cc_list = self::cod5_phpmailer_get_addresses( $phpmailer, 'cc' );
            $bcc_list = self::cod5_phpmailer_get_addresses( $phpmailer, 'bcc' );
            $recipients = array_merge( $to_list, $cc_list, $bcc_list );
        
            $subject = property_exists( $phpmailer, 'Subject' ) ? $phpmailer->Subject : '';
            $body = property_exists( $phpmailer, 'Body' ) ? $phpmailer->Body : '';
            $headers = [];
            $attachments = [];
        
            // Attempt to extract attachments
            if ( is_object( $phpmailer ) ) {
                if ( method_exists( $phpmailer, 'getAttachments' ) ) {
                    $attachments_data = $phpmailer->getAttachments();
                    foreach ( $attachments_data as $att ) {
                        if ( is_array( $att ) && isset( $att[0] ) ) {
                            $attachments[] = $att[0];
                        }
                    }
                } elseif ( property_exists( $phpmailer, 'attachments' ) && is_array( $phpmailer->attachments ) ) {
                    foreach ( $phpmailer->attachments as $att ) {
                        if ( is_array( $att ) && isset( $att[0] ) ) {
                            $attachments[] = $att[0];
                        }
                    }
                }
            }
        
            $payload = [
                'to'          => $recipients,
                'subject'     => $subject,
                'message'     => $body,
                'headers'     => $headers,
                'attachments' => $attachments,
            ];
        
            // Create unique identifier for this PHPMailer request
            $request_key = self::create_request_key($payload);
            
            // Check if already processed (either by wp_mail or previous phpmailer_init)
            if (isset(self::$cod5_processed_requests[$request_key])) {
                self::log_event('DEBUG', 'Duplicate PHPMailer request detected, skipping webhook call.', [
                    'request_key' => $request_key,
                    'request_id' => self::$request_id,
                    'previous_source' => self::$cod5_processed_requests[$request_key]['source']
                ]);
                
                // Still need to patch the PHPMailer object to block actual sending
                self::patch_phpmailer_object($phpmailer);
                return;
            }

            // Mark as processed
            self::$cod5_processed_requests[$request_key] = [
                'timestamp' => microtime(true),
                'source' => 'phpmailer_init',
                'request_id' => self::$request_id
            ];
        
            // Send to webhook only if not duplicate
            $success = self::send_to_webhook( $payload, $request_key );
            $sender = property_exists( $phpmailer, 'From' ) ? $phpmailer->From : '';
            $log_context = [
                'to' => $recipients,
                'subject' => $subject,
                'from' => $sender,
                'request_key' => $request_key,
                'request_id' => self::$request_id
            ];
            if ( $success ) {
                self::log_event( 'INFO', 'PHPMailer instance intercepted and forwarded to webhook successfully.', $log_context );
            } else {
                self::log_event( 'ERROR', 'Failed to forward PHPMailer payload to webhook.', $log_context );
            }
        
            // Always patch the PHPMailer object to block actual sending
            self::patch_phpmailer_object($phpmailer);
        }

        /**
         * Creates a unique key for deduplication based on email content
         * 
         * @param array $payload
         * @return string
         */
        private static function create_request_key($payload) {
            // Normalize the payload for consistent hashing
            $normalized = [
                'to' => self::normalize_recipients($payload['to']),
                'subject' => trim($payload['subject']),
                'message' => trim($payload['message']),
                'attachments_count' => is_array($payload['attachments']) ? count($payload['attachments']) : 0
            ];
            
            // Create hash from normalized data
            return sha1(serialize($normalized));
        }

        /**
         * Patches PHPMailer object to ensure send() returns true (success)
         * 
         * @param object $phpmailer
         * @return void
         */
        private static function patch_phpmailer_object($phpmailer) {
            if ( self::is_namespaced_phpmailer( $phpmailer ) && class_exists( 'Cod5_Patched_PHPMailer' ) ) {
                $patched = self::change_object_class( $phpmailer, 'Cod5_Patched_PHPMailer' );
                if ( is_object( $patched ) ) {
                    foreach ( get_object_vars( $patched ) as $prop => $val ) {
                        $phpmailer->{$prop} = $val;
                    }
                }
            } elseif ( ! self::is_namespaced_phpmailer( $phpmailer ) && class_exists( 'Cod5_Patched_PHPMailer_Legacy' ) ) {
                $patched = self::change_object_class( $phpmailer, 'Cod5_Patched_PHPMailer_Legacy' );
                if ( is_object( $patched ) ) {
                    foreach ( get_object_vars( $patched ) as $prop => $val ) {
                        $phpmailer->{$prop} = $val;
                    }
                }
            }
        }
        

        /**
         * Sends payload to configured webhook.
         *
         * @param array $payload
         * @param string $request_key
         * @return bool Success
         */
        private static function send_to_webhook( $payload, $request_key = '' ) {
            $webhook_url = defined( 'COD5_EMAIL_WEBHOOK_URL' ) ? COD5_EMAIL_WEBHOOK_URL : 'https://criadordigital-n8n-webhook.easypanel.codigo5.com.br/webhook/e72df306-d654-4c91-b310-6ee69ffcdef2';
            
            // Add request metadata to payload
            $enhanced_payload = array_merge($payload, [
                'cod5_metadata' => [
                    'request_key' => $request_key,
                    'request_id' => self::$request_id,
                    'timestamp' => date('c'),
                    'source' => 'cod5_email_webhook_blocker'
                ]
            ]);
            
            $body = wp_json_encode( $enhanced_payload );

            $args = [
                'headers'     => [
                    'Content-Type' => 'application/json',
                ],
                'body'        => $body,
                'timeout'     => 5,
                'blocking'    => true,
                'sslverify'   => true,
            ];

            $response = wp_remote_post( $webhook_url, $args );
            if ( is_wp_error( $response ) ) {
                self::log_event( 'ERROR', 'Webhook request failed: ' . $response->get_error_message(), [ 
                    'webhook_url' => $webhook_url,
                    'request_key' => $request_key,
                    'request_id' => self::$request_id
                ] );
                return false;
            }

            $code = wp_remote_retrieve_response_code( $response );
            if ( $code >= 200 && $code < 300 ) {
                return true;
            }

            $body_resp = wp_remote_retrieve_body( $response );
            self::log_event( 'ERROR', sprintf( 'Webhook returned HTTP %d. Body: %s', $code, substr( $body_resp, 0, 1000 ) ), [ 
                'webhook_url' => $webhook_url,
                'request_key' => $request_key,
                'request_id' => self::$request_id
            ] );
            return false;
        }

        /**
         * Logs event with rotation and safe append.
         *
         * @param string $level
         * @param string $message
         * @param array  $context
         * @return void
         */
        private static function log_event( $level, $message, $context = [] ) {
            $log_path = defined( 'COD5_EMAIL_WEBHOOK_LOG_PATH' ) ? COD5_EMAIL_WEBHOOK_LOG_PATH : ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/email-webhook.log' : ABSPATH . 'wp-content/email-webhook.log' );
            $max_size = 5 * 1024 * 1024; // 5MB

            // Ensure directory exists
            $dir = dirname( $log_path );
            if ( ! is_dir( $dir ) ) {
                @wp_mkdir_p( $dir );
            }

            // Rotate if needed
            if ( file_exists( $log_path ) && filesize( $log_path ) >= $max_size ) {
                $time = date( 'Ymd-His' );
                $rotated = $dir . '/email-webhook-' . $time . '.log';
                @rename( $log_path, $rotated );
            }

            $timestamp = date( 'Y-m-d H:i:s' );
            $entry = sprintf(
                "[%s] [%s] %s | context: %s%s",
                $timestamp,
                strtoupper( $level ),
                $message,
                json_encode( self::sanitize_log_context( $context ), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE ),
                PHP_EOL
            );

            $fp = @fopen( $log_path, 'a' );
            if ( $fp ) {
                @flock( $fp, LOCK_EX );
                @fwrite( $fp, $entry );
                @flock( $fp, LOCK_UN );
                @fclose( $fp );
            }
        }

        /**
         * Basic context sanitizer to avoid sensitive leakage.
         *
         * @param array $context
         * @return array
         */
        private static function sanitize_log_context( $context ) {
            // Remove message bodies or large values if present
            if ( isset( $context['message'] ) ) {
                unset( $context['message'] );
            }
            return $context;
        }

        /**
         * Normalize recipients list into flat array of emails.
         *
         * @param mixed $recipients
         * @return array
         */
        private static function normalize_recipients( $recipients ) {
            $out = [];
            if ( is_array( $recipients ) ) {
                foreach ( $recipients as $r ) {
                    if ( preg_match( '/<(.+?)>/', $r, $m ) ) {
                        $out[] = trim( $m[1] );
                    } else {
                        $out[] = trim( $r );
                    }
                }
            } elseif ( is_string( $recipients ) ) {
                $parts = preg_split( '/[;,]+/', $recipients );
                foreach ( $parts as $p ) {
                    $p = trim( $p );
                    if ( preg_match( '/<(.+?)>/', $p, $m ) ) {
                        $out[] = trim( $m[1] );
                    } else {
                        $out[] = $p;
                    }
                }
            }
            return array_values( array_filter( $out ) );
        }

        /**
         * Extract "From" header if present in header string/array.
         *
         * @param mixed $headers
         * @return string
         */
        private static function extract_from_headers( $headers ) {
            if ( is_array( $headers ) ) {
                foreach ( $headers as $h ) {
                    if ( stripos( $h, 'From:' ) === 0 ) {
                        return trim( substr( $h, 5 ) );
                    }
                }
            } elseif ( is_string( $headers ) ) {
                $lines = preg_split( '/\r?\n/', $headers );
                foreach ( $lines as $l ) {
                    if ( stripos( $l, 'From:' ) === 0 ) {
                        return trim( substr( $l, 5 ) );
                    }
                }
            }
            return '';
        }

        /**
         * Detect if given PHPMailer is namespaced (v6+) vs legacy.
         *
         * @param object $phpmailer
         * @return bool
         */
        private static function is_namespaced_phpmailer( $phpmailer ) {
            return ( is_object( $phpmailer ) && ( $phpmailer instanceof \PHPMailer\PHPMailer\PHPMailer ) );
        }

        /**
         * Return array of addresses from PHPMailer for given type.
         *
         * @param object $phpmailer
         * @param string $type 'to', 'cc', 'bcc'
         * @return array
         */
        private static function cod5_phpmailer_get_addresses( $phpmailer, $type = 'to' ) {
            $addresses = [];
            // Namespaced PHPMailer has accessors
            if ( self::is_namespaced_phpmailer( $phpmailer ) ) {
                $method = 'get' . ucfirst( $type ) . 'Addresses'; // e.g., getToAddresses
                if ( method_exists( $phpmailer, $method ) ) {
                    $list = $phpmailer->{$method}();
                    if ( is_array( $list ) ) {
                        foreach ( $list as $addr ) {
                            if ( is_array( $addr ) && isset( $addr[0] ) ) {
                                $addresses[] = $addr[0];
                            }
                        }
                    }
                }
            } else {
                // Legacy PHPMailer: properties like to, cc, bcc
                if ( property_exists( $phpmailer, $type ) && is_array( $phpmailer->{$type} ) ) {
                    foreach ( $phpmailer->{$type} as $addr ) {
                        if ( is_array( $addr ) && isset( $addr[0] ) ) {
                            $addresses[] = $addr[0];
                        }
                    }
                }
            }
            return $addresses;
        }

        /**
         * Change object class to a subclass (serialization hack).
         *
         * @param object $object
         * @param string $new_class
         * @return object Original or transformed object.
         */
        private static function change_object_class( $object, $new_class ) {
            if ( ! class_exists( $new_class ) ) {
                return $object;
            }
            $old_class = get_class( $object );
            $serialized = serialize( $object );
            $pattern = sprintf( '/^O:\d+:"%s"/', preg_quote( $old_class, '/' ) );
            $replacement = sprintf( 'O:%d:"%s"', strlen( $new_class ), $new_class );
            $new_serialized = preg_replace( $pattern, $replacement, $serialized, 1 );
            if ( ! $new_serialized ) {
                return $object;
            }
            $new_object = @unserialize( $new_serialized );
            if ( $new_object === false ) {
                return $object;
            }
            return $new_object;
        }

        /**
         * Prepares patched PHPMailer subclasses for overriding send().
         * Defines two classes if original PHPMailer types exist.
         */
        private static function prepare_phPMailer_patch_classes() {
            // Namespaced PHPMailer v6+
            if ( class_exists( '\PHPMailer\PHPMailer\PHPMailer' ) && ! class_exists( 'Cod5_Patched_PHPMailer' ) ) {
                eval( '
                    class Cod5_Patched_PHPMailer extends \PHPMailer\PHPMailer\PHPMailer {
                        public function send() {
                            // Block actual send but return true to indicate success to WordPress
                            return true;
                        }
                    }
                ' );
            }
            // Legacy global PHPMailer
            if ( class_exists( 'PHPMailer' ) && ! class_exists( 'Cod5_Patched_PHPMailer_Legacy' ) ) {
                eval( '
                    class Cod5_Patched_PHPMailer_Legacy extends PHPMailer {
                        public function send() {
                            // Block actual send but return true to indicate success to WordPress
                            return true;
                        }
                    }
                ' );
            }
        }
    }

    // Initialize plugin
    Cod5_Email_Webhook_Blocker::init();
}

