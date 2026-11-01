from flask import Flask, render_template, jsonify, request, redirect, url_for, send_from_directory, make_response
import sys
import os
import logging
import hmac
import re
from datetime import datetime
import json
from configparser import ConfigParser
import werkzeug.serving
from functools import wraps

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ProxyCat import run_server
from modules.auth import PASSWORD_HASH_PREFIX, UNCHANGED_PASSWORD, hash_proxy_password
from modules.modules import CURRENT_VERSION, load_config, check_proxies, get_message, load_ip_list
from modules.proxyserver import AsyncProxyServer
import asyncio
import threading
import time

app = Flask(__name__, 
           template_folder='web/templates',
           static_folder='web/static') 

werkzeug.serving.WSGIRequestHandler.log = lambda self, type, message, *args: None
logging.getLogger('werkzeug').setLevel(logging.ERROR)

config = load_config('config/config.ini')
server = AsyncProxyServer(config)

def get_config_path(filename):
    return os.path.join('config', filename)

log_file = 'logs/proxycat.log'
os.makedirs('logs', exist_ok=True)
log_messages = []
max_log_messages = 10000
service_lifecycle_lock = threading.RLock()

class CustomFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        return datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')

def setup_logging():
    file_formatter = CustomFormatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setFormatter(file_formatter)

    console_handler = logging.StreamHandler()
    console_formatter = CustomFormatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)

    memory_handler = MemoryHandler()
    memory_handler.setFormatter(CustomFormatter('%(message)s'))

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(memory_handler)

class MemoryHandler(logging.Handler):
    def emit(self, record):
        global log_messages
        log_messages.append({
            'time': datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S'),
            'level': record.levelname,
            'message': self.format(record)
        })
        if len(log_messages) > max_log_messages:
            log_messages = log_messages[-max_log_messages:]

def get_management_token():
    """Return the management credential supplied by an API or browser client."""
    authorization = request.headers.get('Authorization', '')
    scheme, _, credential = authorization.partition(' ')
    if scheme.lower() == 'bearer' and credential:
        return credential.strip()

    header_token = request.headers.get('X-ProxyCat-Token', '')
    if header_token:
        return header_token.strip()

    query_token = request.args.get('token', '')
    if query_token:
        return query_token

    return request.cookies.get('proxycat_management_token', '')


def authorize_management_request():
    """Validate the management token and return a Flask error response on failure."""
    configured_token = str(server.config.get('token', '')).strip()
    if not configured_token:
        return jsonify({
            'status': 'error',
            'message': get_message('management_auth_not_configured', server.language)
        }), 503

    supplied_token = get_management_token()
    if not supplied_token or not hmac.compare_digest(supplied_token, configured_token):
        return jsonify({
            'status': 'error',
            'message': get_message('invalid_token', server.language)
        }), 401

    return None


def require_token(f):
    """Protect a browser route with the configured management credential."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        error_response = authorize_management_request()
        if error_response:
            return error_response
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def protect_management_api():
    """Apply management authorization consistently to every API endpoint."""
    if request.path == '/api' or request.path.startswith('/api/'):
        return authorize_management_request()
    return None

@app.route('/')
def root():
    token = request.args.get('token')
    if token:
        return redirect(url_for('web', token=token))
    return redirect('/web')

@app.route('/web')
@require_token
def web():
    response = make_response(render_template('index.html'))
    if request.args.get('token'):
        response.set_cookie(
            'proxycat_management_token',
            request.args['token'],
            httponly=True,
            secure=(
                request.is_secure
                or server.config.get('management_cookie_secure', 'False').lower() == 'true'
            ),
            samesite='Strict',
        )
    return response

@app.route('/api/status')
def get_status():
    with open('config/config.ini', 'r', encoding='utf-8') as f:
        config_content = f.read()
        
    config = ConfigParser()
    config.read('config/config.ini', encoding='utf-8')
    
    server_config = dict(config.items('Server')) if config.has_section('Server') else {}
    
    current_proxy = server.current_proxy
    if not current_proxy and not server.use_getip:
        if hasattr(server, 'proxies') and server.proxies:
            current_proxy = server.proxies[0]
        else:
            current_proxy = get_message('no_proxy', server.language)
    
    
    time_left = server.time_until_next_switch()
    if server.mode == 'loadbalance':
        
        if time_left == float('inf'):
            time_left = -1
    
    public_server_config = dict(server_config)
    public_server_config.pop('token', None)

    return jsonify({
        'current_proxy': current_proxy,
        'mode': server.mode,
        'port': int(server_config.get('port', '1080')),
        'interval': server.interval,
        'time_left': time_left,
        'total_proxies': len(server.proxies) if hasattr(server, 'proxies') else 0,
        'use_getip': server.use_getip,
        'getip_url': getattr(server, 'getip_url', '') if getattr(server, 'use_getip', False) else '',
        'auth_required': server.auth_required,
        'display_level': int(server_config.get('display_level', '1')),
        'service_status': 'running' if server.running else 'stopped',
        'config': public_server_config
    })

@app.route('/api/config', methods=['POST'])
def save_config():
    try:
        new_config = request.get_json()
        current_config = load_config('config/config.ini')
        port_changed = str(new_config.get('port', '')) != str(current_config.get('port', ''))
        mode_changed = new_config.get('mode', '') != current_config.get('mode', '')
        use_getip_changed = (new_config.get('use_getip', 'False').lower() == 'true') != (current_config.get('use_getip', 'False').lower() == 'true')
        proxy_file_changed = new_config.get('proxy_file', current_config.get('proxy_file', 'ip.txt')) != current_config.get('proxy_file', 'ip.txt')
        
        config_parser = ConfigParser()
        config_parser.read('config/config.ini', encoding='utf-8')
        
        if not config_parser.has_section('Server'):
            config_parser.add_section('Server')
            
        for key, value in new_config.items():
            if key != 'users':
                config_parser.set('Server', key, str(value))
        
        with open('config/config.ini', 'w', encoding='utf-8') as f:
            config_parser.write(f)
            
        
        old_mode = server.mode
        old_use_getip = server.use_getip
        
        
        server.config = load_config('config/config.ini')
        server._init_config_values(server.config)
        
        
        if mode_changed or use_getip_changed or proxy_file_changed:
            server._handle_mode_change()
            
            
            if new_config.get('mode') == 'loadbalance':
                server.last_switch_time = time.time()
                server.last_switch_attempt = 0
        
        return jsonify({
            'status': 'success',
            'port_changed': port_changed,
            'service_status': 'running' if server.running else 'stopped'
        })
        
    except Exception as e:
        logging.error(f"Error saving config: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/proxies', methods=['GET', 'POST'])
def handle_proxies():
    if request.method == 'POST':
        try:
            proxies = request.json.get('proxies', [])
            proxy_file = get_config_path(os.path.basename(server.proxy_file))
            with open(proxy_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(proxies))
            if not server._reload_proxies():
                return jsonify({
                    'status': 'error',
                    'message': get_message('proxy_save_failed', server.language, 'No valid proxy entries')
                }), 400
            return jsonify({
                'status': 'success',
                'message': get_message('proxy_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': get_message('proxy_save_failed', server.language, str(e))
            })
    else:
        try:
            proxy_file = get_config_path(os.path.basename(server.proxy_file))
            with open(proxy_file, 'r', encoding='utf-8') as f:
                proxies = f.read().splitlines()
            return jsonify({'proxies': proxies})
        except Exception:
            return jsonify({'proxies': []})

@app.route('/api/check_proxies')
def check_proxies_api():
    try:
        test_url = request.args.get('test_url', 'https://www.baidu.com')
        valid_proxies = asyncio.run(check_proxies(server.proxies, test_url))
        total_valid = len(valid_proxies)
        return jsonify({
            'status': 'success',
            'valid_proxies': valid_proxies,
            'total': total_valid,
            'message': get_message('proxy_check_result', server.language, total_valid)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('proxy_check_failed', server.language, str(e))
        })

@app.route('/api/ip_lists', methods=['GET', 'POST'])
def handle_ip_lists():
    if request.method == 'POST':
        try:
            list_type = request.json.get('type')
            ip_list = request.json.get('list', [])
            base_filename = os.path.basename(server.whitelist_file if list_type == 'whitelist' else server.blacklist_file)
            filename = get_config_path(base_filename)
            
            with open(filename, 'w', encoding='utf-8') as f:
                f.write('\n'.join(ip_list))
            
            if list_type == 'whitelist':
                server.whitelist = load_ip_list(filename)
            else:
                server.blacklist = load_ip_list(filename)
                
            return jsonify({
                'status': 'success',
                'message': get_message('ip_list_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': get_message('ip_list_save_failed', server.language, str(e))
            })
    else:
        whitelist_file = get_config_path(os.path.basename(server.whitelist_file))
        blacklist_file = get_config_path(os.path.basename(server.blacklist_file))
        return jsonify({
            'whitelist': list(load_ip_list(whitelist_file)), 
            'blacklist': list(load_ip_list(blacklist_file)) 
        })

@app.route('/api/logs')
def get_logs():
    try:
        start = int(request.args.get('start', 0))
        limit = int(request.args.get('limit', 100))
        level = request.args.get('level', 'ALL')
        search = request.args.get('search', '').lower()
        
        filtered_logs = log_messages
        
        if level != 'ALL':
            filtered_logs = [log for log in log_messages if log['level'] == level]
        
        if search:
            filtered_logs = [
                log for log in filtered_logs 
                if search in log['message'].lower() or 
                   search in log['level'].lower() or 
                   search in log['time'].lower()
            ]
        
        return jsonify({
            'logs': filtered_logs[start:start+limit],
            'total': len(filtered_logs),
            'status': 'success'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        })

@app.route('/api/logs/clear', methods=['POST'])
def clear_logs():
    try:
        global log_messages
        log_messages = []
        
        with open(log_file, 'w', encoding='utf-8') as f:
            f.write('')
            
        return jsonify({
            'status': 'success',
            'message': get_message('logs_cleared', server.language)
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('clear_logs_failed', server.language, str(e))
        })

@app.route('/api/switch_proxy')
def switch_proxy():
    try:
        result = asyncio.run(server.switch_proxy())
        if result:
            return jsonify({
                'status': 'success',
                'current_proxy': server.current_proxy,
                'message': get_message('switch_success', server.language)
            })
        else:
            return jsonify({
                'status': 'error',
                'message': get_message('switch_failed', server.language, 'Proxy switch not needed or in cooldown')
            })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('switch_failed', server.language, str(e))
        })

def start_proxy_service(timeout=5):
    """Start the proxy thread and wait for the listening socket to be ready."""
    with service_lifecycle_lock:
        if server.running:
            return True, None

        old_thread = getattr(server, 'proxy_thread', None)
        if old_thread and old_thread.is_alive():
            old_thread.join(timeout=timeout)
            if old_thread.is_alive():
                return False, 'Previous proxy service is still shutting down'

        server.stop_server = False
        server.last_start_error = None
        server.proxy_thread = threading.Thread(
            target=lambda: asyncio.run(run_server(server)),
            daemon=True,
            name='proxycat-server',
        )
        server.proxy_thread.start()

        deadline = time.time() + timeout
        while time.time() < deadline:
            if server.running:
                return True, None
            if server.last_start_error:
                return False, server.last_start_error
            if not server.proxy_thread.is_alive():
                break
            time.sleep(0.05)

        return False, server.last_start_error or 'Timed out waiting for the proxy port to listen'


def stop_proxy_service(timeout=5):
    """Stop the proxy server on its owning event loop and wait for release."""
    with service_lifecycle_lock:
        proxy_thread = getattr(server, 'proxy_thread', None)
        loop = server.event_loop

        if loop and loop.is_running():
            future = asyncio.run_coroutine_threadsafe(server.stop(), loop)
            try:
                future.result(timeout=timeout)
            except Exception as e:
                return False, str(e)

        if proxy_thread and proxy_thread.is_alive():
            proxy_thread.join(timeout=timeout)
            if proxy_thread.is_alive():
                return False, 'Timed out waiting for the proxy port to be released'

        server.proxy_thread = None
        return True, None


@app.route('/api/service', methods=['POST'])
def control_service():
    try:
        action = request.json.get('action')

        if action == 'start':
            if server.running:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_already_running', server.language),
                    'service_status': 'running'
                })

            success, error = start_proxy_service()
            if success:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_start_success', server.language),
                    'service_status': 'running'
                })

            return jsonify({
                'status': 'error',
                'message': get_message('service_start_failed', server.language, error),
                'service_status': 'stopped'
            }), 409

        if action == 'stop':
            if not server.running and not (
                getattr(server, 'proxy_thread', None)
                and server.proxy_thread.is_alive()
            ):
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_not_running', server.language),
                    'service_status': 'stopped'
                })

            success, error = stop_proxy_service()
            if success:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_stop_success', server.language),
                    'service_status': 'stopped'
                })

            return jsonify({
                'status': 'error',
                'message': get_message('service_stop_failed', server.language, error),
                'service_status': 'running' if server.running else 'stopped'
            }), 500

        if action == 'restart':
            success, error = stop_proxy_service()
            if not success:
                return jsonify({
                    'status': 'error',
                    'message': get_message('service_restart_failed', server.language, error),
                    'service_status': 'running' if server.running else 'stopped'
                }), 500

            success, error = start_proxy_service()
            if success:
                return jsonify({
                    'status': 'success',
                    'message': get_message('service_restart_success', server.language),
                    'service_status': 'running'
                })

            return jsonify({
                'status': 'error',
                'message': get_message('service_restart_failed', server.language, error),
                'service_status': 'stopped'
            }), 409

        return jsonify({
            'status': 'error',
            'message': get_message('invalid_action', server.language)
        }), 400
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('operation_failed', server.language, str(e))
        }), 500


@app.route('/api/language', methods=['POST'])
def change_language():
    try:
        new_language = request.json.get('language', 'cn')
        if new_language not in ['cn', 'en']:
            return jsonify({
                'status': 'error',
                'message': get_message('unsupported_language', server.language)
            })
        
        config = ConfigParser()
        config.read('config/config.ini', encoding='utf-8')
        
        if 'Server' not in config:
            config.add_section('Server')
        
        config.set('Server', 'language', new_language)
        
        with open('config/config.ini', 'w', encoding='utf-8') as f:
            config.write(f)
            
        server.language = new_language
        
        return jsonify({
            'status': 'success',
            'language': new_language
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('operation_failed', server.language, str(e))
        })

@app.route('/api/version')
def check_version():
    try:
        import re
        import httpx
        from packaging import version
        import logging
        
        httpx_logger = logging.getLogger('httpx')
        original_level = httpx_logger.level
        httpx_logger.setLevel(logging.WARNING)
        
        try:
            client = httpx.Client(transport=httpx.HTTPTransport(retries=3))
            response = client.get("https://y.shironekosan.cn/1.html", timeout=10)
            response.raise_for_status()
            content = response.text
            
            match = re.search(r'<p>(ProxyCat-V\d+\.\d+\.\d+)</p>', content)
            if match:
                latest_version = match.group(1)
                is_latest = version.parse(latest_version.split('-V')[1]) <= version.parse(CURRENT_VERSION.split('-V')[1])
                
                return jsonify({
                    'status': 'success',
                    'is_latest': is_latest,
                    'current_version': CURRENT_VERSION,
                    'latest_version': latest_version
                })
            else:
                return jsonify({
                    'status': 'error',
                    'message': get_message('version_info_not_found', server.language)
                })
        finally:
            httpx_logger.setLevel(original_level)
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': get_message('update_check_error', server.language, str(e))
        })

@app.route('/api/users', methods=['GET', 'POST'])
def handle_users():
    if request.method == 'POST':
        try:
            if server.users_from_environment:
                return jsonify({
                    'status': 'error',
                    'message': get_message('proxy_users_managed_by_environment', server.language)
                }), 409

            request_data = request.get_json(silent=True) or {}
            users = request_data.get('users', {})
            if not isinstance(users, dict):
                raise ValueError('users must be an object')
            if server.require_proxy_auth and not users:
                return jsonify({
                    'status': 'error',
                    'message': get_message('proxy_auth_users_required', server.language)
                }), 400

            config = ConfigParser()
            config.read('config/config.ini', encoding='utf-8')
            existing_users = (
                dict(config.items('Users')) if config.has_section('Users') else {}
            )

            normalized_users = {}
            for username, password in users.items():
                username = str(username).strip()
                password = str(password)
                if not username or not password or len(password) > 1024:
                    raise ValueError(get_message('invalid_proxy_user', server.language))
                if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', username):
                    raise ValueError(get_message('invalid_proxy_user', server.language))

                if password == UNCHANGED_PASSWORD:
                    existing_password = existing_users.get(username)
                    if existing_password is None:
                        raise ValueError(get_message('invalid_proxy_user', server.language))
                    if existing_password.startswith(PASSWORD_HASH_PREFIX):
                        normalized_users[username] = existing_password
                    else:
                        normalized_users[username] = hash_proxy_password(existing_password)
                else:
                    normalized_users[username] = hash_proxy_password(password)

            users = normalized_users
            
            sections_to_preserve = {}
            for section in config.sections():
                if section != 'Users':
                    sections_to_preserve[section] = dict(config.items(section))

            config = ConfigParser()
            
            for section, options in sections_to_preserve.items():
                config.add_section(section)
                for key, value in options.items():
                    config.set(section, key, value)
            
            if users:
                config.add_section('Users')
                for username, password in users.items():
                    config.set('Users', username, password)
            
            with open('config/config.ini', 'w', encoding='utf-8') as f:
                config.write(f)
            
            server.users = users
            server.auth_required = server.require_proxy_auth or bool(users)
            
            if hasattr(server, 'proxy_server') and server.proxy_server:
                server.proxy_server.users = users
                server.proxy_server.auth_required = (
                    server.require_proxy_auth or bool(users)
                )
            
            return jsonify({
                'status': 'success',
                'message': get_message('users_save_success', server.language)
            })
        except Exception as e:
            return jsonify({
                'status': 'error',
                'message': get_message('users_save_failed', server.language, str(e))
            })
    else:
        try:
            return jsonify({
                'users': sorted(server.users.keys()),
                'managed_by_environment': server.users_from_environment,
            })
        except Exception as e:
            logging.error(f"Error getting users: {e}")
            return jsonify({'users': [], 'managed_by_environment': False})

@app.route('/static/<path:path>')
def send_static(path):
    return send_from_directory('web/static', path)

def run_proxy_server():
    try:
        asyncio.run(run_server(server))
    except KeyboardInterrupt:
        logging.info(get_message('user_interrupt', server.language))
    except Exception as e:
        logging.error(f"Proxy server error: {e}")

if __name__ == '__main__':
    setup_logging()
    web_port = int(config.get('web_port', '5000'))
    web_url = f"http://127.0.0.1:{web_port}"

    logging.info(get_message('web_panel_url', server.language, web_url))
    logging.info(get_message('web_panel_notice', server.language))

    try:
        # Bind the management port before starting the proxy thread.  This is
        # the authoritative availability check and avoids leaving a partially
        # started application when another process already owns web_port.
        web_server = werkzeug.serving.make_server(
            '0.0.0.0', web_port, app, threaded=True
        )
    except OSError as error:
        logging.error(f"Web server port {web_port} is unavailable: {error}")
        raise SystemExit(1)

    success, error = start_proxy_service()
    if not success:
        logging.error(get_message('service_start_failed', server.language, error))

    try:
        web_server.serve_forever()
    finally:
        stop_proxy_service()
