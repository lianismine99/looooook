import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse, quote, unquote
import socket
import subprocess
import json
import ssl
import re
from typing import List, Tuple, Optional, Dict, Any
import logging
import hashlib

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('stream_check.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 配置参数
class Config:
    # UA配置
    USER_AGENT_URL = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    # 超时配置
    TIMEOUT_FETCH = 10
    TIMEOUT_CHECK = 8
    TIMEOUT_CONNECT = 5
    
    # 线程配置
    MAX_WORKERS = 30
    
    # 重试配置
    MAX_RETRIES = 2
    RETRY_DELAY = 1
    
    # 统计配置
    MIN_SUCCESS_RATE = 0.3  # 最低成功率，低于此值的主机会被加入黑名单
    
    # 缓存配置
    CACHE_EXPIRE_HOURS = 24

class StreamChecker:
    def __init__(self):
        self.timestart = datetime.now()
        self.blacklist_dict: Dict[str, int] = {}
        self.url_statistics: List[str] = []
        self.success_cache: Dict[str, Tuple[float, datetime]] = {}
        self.failed_cache: Dict[str, datetime] = {}
        self.cache_file = "check_cache.json"
        self.load_cache()
        
    def load_cache(self):
        """加载检测缓存"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    cache_data = json.load(f)
                    for url, data in cache_data.get('success', {}).items():
                        cache_time = datetime.fromisoformat(data['time'])
                        if (datetime.now() - cache_time).total_seconds() < Config.CACHE_EXPIRE_HOURS * 3600:
                            self.success_cache[url] = (data['elapsed'], cache_time)
                    for url, cache_time_str in cache_data.get('failed', {}).items():
                        cache_time = datetime.fromisoformat(cache_time_str)
                        if (datetime.now() - cache_time).total_seconds() < Config.CACHE_EXPIRE_HOURS * 3600:
                            self.failed_cache[url] = cache_time
        except Exception as e:
            logger.warning(f"加载缓存失败: {e}")
    
    def save_cache(self):
        """保存检测缓存"""
        try:
            cache_data = {
                'success': {
                    url: {'elapsed': elapsed, 'time': cache_time.isoformat()}
                    for url, (elapsed, cache_time) in self.success_cache.items()
                },
                'failed': {
                    url: cache_time.isoformat()
                    for url, cache_time in self.failed_cache.items()
                }
            }
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"保存缓存失败: {e}")
    
    def get_url_hash(self, url: str) -> str:
        """生成URL的哈希值用于缓存键"""
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    def read_txt_to_array(self, file_name: str) -> List[str]:
        """读取文本文件到数组"""
        try:
            with open(file_name, 'r', encoding='utf-8') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            logger.error(f"读取文件失败 {file_name}: {e}")
            return []
    
    def read_txt_file(self, file_path: str) -> List[str]:
        """读取直播源文件，过滤无效行"""
        skip_patterns = [r'#genre#', r'#EXTINF:-1', r'"ext"']
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = []
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # 跳过包含特定模式的行
                    if any(re.search(pattern, line) for pattern in skip_patterns):
                        continue
                    
                    # 必须包含协议和分隔符
                    if '://' in line and ',' in line:
                        lines.append(line)
                return lines
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []
    
    def get_host_from_url(self, url: str) -> str:
        """从URL中提取主机名"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            # 处理IPv6地址
            if host.startswith('[') and host.endswith(']'):
                host = host[1:-1]
            
            # 移除端口号（如果不是IPv6）
            if ':' in host and not host.count(':') > 1:
                host = host.split(':')[0]
            
            return host
        except Exception:
            return ""
    
    def is_ip_address(self, host: str) -> Tuple[bool, Optional[str]]:
        """判断是否为IP地址并返回类型"""
        try:
            # 尝试解析为IPv4
            socket.inet_pton(socket.AF_INET, host)
            return True, "IPv4"
        except socket.error:
            try:
                # 尝试解析为IPv6
                socket.inet_pton(socket.AF_INET6, host)
                return True, "IPv6"
            except socket.error:
                return False, None
    
    def record_host_failure(self, host: str):
        """记录主机失败次数"""
        if host:
            self.blacklist_dict[host] = self.blacklist_dict.get(host, 0) + 1
            
            # 如果失败次数过多，记录警告
            if self.blacklist_dict[host] >= 5:
                logger.warning(f"主机 {host} 失败次数过多: {self.blacklist_dict[host]}")
    
    def create_ssl_context(self):
        """创建SSL上下文，支持更多协议"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        return context
    
    def check_http_url_with_retry(self, url: str, timeout: int, ip_version: Optional[int] = None) -> Optional[bool]:
        """带重试的HTTP/HTTPS检测"""
        for retry in range(Config.MAX_RETRIES):
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        "User-Agent": Config.USER_AGENT,
                        "Accept": "*/*",
                        "Connection": "close",
                        "Accept-Encoding": "gzip, deflate"
                    }
                )
                
                # 设置超时
                socket.setdefaulttimeout(timeout)
                
                # 创建opener
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=self.create_ssl_context())
                )
                
                with opener.open(req) as resp:
                    status = resp.status
                    content_type = resp.headers.get('Content-Type', '')
                    
                    # 检查状态码
                    if 200 <= status < 300:
                        # 对于流媒体，检查内容类型
                        if any(x in content_type.lower() for x in ['video', 'audio', 'application/octet-stream']):
                            return True
                        # 尝试读取少量数据检查是否是流
                        try:
                            data = resp.read(1024)
                            if data:
                                return True
                        except:
                            pass
                        return True
                    elif status in [301, 302, 307, 308]:
                        # 处理重定向
                        redirect_url = resp.headers.get('Location')
                        if redirect_url:
                            if not redirect_url.startswith(('http://', 'https://')):
                                parsed = urlparse(url)
                                redirect_url = f"{parsed.scheme}://{parsed.netloc}{redirect_url}"
                            if retry < Config.MAX_RETRIES - 1:
                                return self.check_http_url_with_retry(redirect_url, timeout, ip_version)
                    return False
                    
            except urllib.error.HTTPError as e:
                if e.code in [401, 403, 404]:
                    return False
                if retry == Config.MAX_RETRIES - 1:
                    return None
            except (socket.timeout, urllib.error.URLError, ConnectionResetError, ssl.SSLError) as e:
                if retry == Config.MAX_RETRIES - 1:
                    return None
                time.sleep(Config.RETRY_DELAY)
            except Exception as e:
                if retry == Config.MAX_RETRIES - 1:
                    logger.debug(f"HTTP检测异常 {url}: {str(e)[:100]}")
                    return None
                time.sleep(Config.RETRY_DELAY)
        
        return None
    
    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> Optional[bool]:
        """检测RTMP/RTSP链接"""
        for retry in range(Config.MAX_RETRIES):
            try:
                # 检查ffmpeg是否可用
                try:
                    subprocess.run(['ffprobe', '-version'], 
                                 stdout=subprocess.DEVNULL, 
                                 stderr=subprocess.DEVNULL, 
                                 timeout=2)
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    logger.warning("ffprobe不可用，使用简化RTMP检测")
                    # 简化检测：尝试TCP连接
                    parsed = urlparse(url)
                    host, port = parsed.hostname, parsed.port or (1935 if url.startswith('rtmp') else 554)
                    
                    with socket.create_connection((host, port), timeout=Config.TIMEOUT_CONNECT) as sock:
                        return True
                
                # 使用ffprobe进行详细检测
                cmd = ['ffprobe', '-v', 'quiet', '-timeout', f'{int(timeout * 1000000)}',
                       '-select_streams', 'v:0', '-show_entries', 'stream=codec_name',
                       '-of', 'json', url]
                
                result = subprocess.run(cmd, capture_output=True, timeout=timeout + 2)
                
                if result.returncode == 0:
                    try:
                        data = json.loads(result.stdout)
                        if 'streams' in data and len(data['streams']) > 0:
                            return True
                    except json.JSONDecodeError:
                        # 只要能连接成功就认为是有效的
                        return True
                return False
                
            except subprocess.TimeoutExpired:
                if retry == Config.MAX_RETRIES - 1:
                    return None
                time.sleep(Config.RETRY_DELAY)
            except Exception as e:
                if retry == Config.MAX_RETRIES - 1:
                    logger.debug(f"RTMP/RTSP检测异常 {url}: {str(e)[:100]}")
                    return None
                time.sleep(Config.RETRY_DELAY)
        
        return None
    
    def check_rtp_url(self, url: str, timeout: int) -> Optional[bool]:
        """检测RTP链接"""
        try:
            parsed = urlparse(url)
            host, port = parsed.hostname, parsed.port or 5004
            
            if not host or not port:
                return False
            
            # 创建socket
            is_ip, ip_type = self.is_ip_address(host)
            
            if is_ip and ip_type == "IPv6":
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            sock.settimeout(Config.TIMEOUT_CONNECT)
            
            # 尝试发送简单数据包
            try:
                sock.connect((host, port))
                # 发送空的RTP头（版本2，无负载类型）
                rtp_header = bytes([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
                sock.send(rtp_header)
                
                # 尝试接收响应（某些RTP服务器会响应）
                try:
                    data = sock.recv(1024)
                    if data:
                        return True
                except socket.timeout:
                    # 没有响应也可能是正常的
                    pass
                
                return True
            finally:
                sock.close()
                
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"RTP检测异常 {url}: {str(e)[:100]}")
            return False
    
    def check_special_protocol(self, url: str, timeout: int) -> Optional[bool]:
        """检测特殊协议链接"""
        try:
            parsed = urlparse(url)
            host, port = parsed.hostname, parsed.port or 80
            
            if not host or not port:
                return False
            
            # 根据协议选择端口
            if url.startswith("p2p"):
                port = port or 8000
            elif url.startswith("p3p"):
                port = port or 8080
            
            # 创建socket连接
            is_ip, ip_type = self.is_ip_address(host)
            
            if is_ip and ip_type == "IPv6":
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            sock.settimeout(Config.TIMEOUT_CONNECT)
            sock.connect((host, port))
            
            # 发送协议特定的握手信息
            if url.startswith("p3p"):
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {Config.USER_AGENT}\r\nConnection: close\r\n\r\n"
                sock.send(request.encode())
                
                # 接收响应
                response = sock.recv(1024)
                if response:
                    return True
            
            sock.close()
            return True
            
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"特殊协议检测异常 {url}: {str(e)[:100]}")
            return False
    
    def check_url(self, url: str) -> Tuple[Optional[float], bool]:
        """主检测函数"""
        url_hash = self.get_url_hash(url)
        
        # 检查缓存
        if url_hash in self.success_cache:
            elapsed, cache_time = self.success_cache[url_hash]
            if (datetime.now() - cache_time).total_seconds() < 3600:  # 1小时内缓存有效
                return elapsed, True
        
        if url_hash in self.failed_cache:
            cache_time = self.failed_cache[url_hash]
            if (datetime.now() - cache_time).total_seconds() < 1800:  # 30分钟内缓存有效
                return None, False
        
        start_time = time.time()
        result = None
        elapsed = None
        
        try:
            # 统一URL编码
            encoded_url = quote(unquote(url), safe=':/?&=#')
            
            # 根据协议类型选择检测方法
            if url.startswith(("http://", "https://")):
                result = self.check_http_url_with_retry(encoded_url, Config.TIMEOUT_CHECK)
            elif url.startswith(("rtmp://", "rtsp://")):
                result = self.check_rtmp_rtsp_url(encoded_url, Config.TIMEOUT_CHECK)
            elif url.startswith("rtp://"):
                result = self.check_rtp_url(encoded_url, Config.TIMEOUT_CHECK)
            elif url.startswith(("p2p://", "p3p://")):
                result = self.check_special_protocol(encoded_url, Config.TIMEOUT_CHECK)
            else:
                # 未知协议，尝试通用TCP检测
                result = self.check_special_protocol(encoded_url, Config.TIMEOUT_CHECK)
            
            elapsed = (time.time() - start_time) * 1000
            
            # 处理结果
            if result is True:
                self.success_cache[url_hash] = (elapsed, datetime.now())
                return elapsed, True
            elif result is False:
                self.failed_cache[url_hash] = datetime.now()
                host = self.get_host_from_url(url)
                self.record_host_failure(host)
                return None, False
            else:
                # 超时或未知，暂时标记为有效但记录
                logger.debug(f"链接检测超时或未知: {url}")
                return elapsed, True
                
        except Exception as e:
            logger.error(f"检测链接异常 {url}: {e}")
            return None, False
    
    def process_m3u_content(self, text: str, source_url: str) -> List[str]:
        """处理M3U格式内容"""
        lines = []
        try:
            if "#EXTM3U" not in text[:100]:
                return lines
            
            current_name = ""
            for line in text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith("#EXTINF"):
                    # 提取频道名称
                    match = re.search(r',(.+)$', line)
                    if match:
                        current_name = match.group(1).strip()
                elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://', 
                                    'rtp://', 'p2p://', 'p3p://')):
                    if current_name:
                        lines.append(f"{current_name},{line}")
                        current_name = ""
                    else:
                        lines.append(f"Unknown,{line}")
            
            logger.info(f"从 {source_url} 解析出 {len(lines)} 个M3U链接")
            return lines
            
        except Exception as e:
            logger.error(f"解析M3U内容失败: {e}")
            return []
    
    def fetch_remote_urls(self, urls: List[str]):
        """获取远程URL内容"""
        all_lines = []
        
        for url in urls:
            try:
                logger.info(f"获取远程URL: {url}")
                encoded_url = quote(unquote(url), safe=':/?&=#')
                req = urllib.request.Request(
                    encoded_url,
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    
                    if "#EXTM3U" in content[:100]:
                        lines = self.process_m3u_content(content, url)
                    else:
                        # 处理普通文本格式
                        lines = []
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and '://' in line and ',' in line and '#genre#' not in line:
                                lines.append(line)
                    
                    count = len(lines)
                    self.url_statistics.append(f"{count},{url}")
                    all_lines.extend(lines)
                    logger.info(f"从 {url} 获取到 {count} 个链接")
                    
            except Exception as e:
                logger.error(f"获取远程URL失败 {url}: {e}")
        
        return all_lines
    
    def clean_and_deduplicate(self, lines: List[str]) -> List[str]:
        """清理和去重链接"""
        # 分割多个链接
        new_lines = []
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            
            name, urls = line.split(',', 1)
            name = name.strip()
            
            # 分割多个URL（用#分隔）
            for url_part in urls.split('#'):
                url_part = url_part.strip()
                if '://' in url_part:
                    new_lines.append(f"{name},{url_part}")
        
        # 移除$符号及其后的内容
        cleaned_lines = []
        for line in new_lines:
            if '$' in line:
                line = line[:line.rfind('$')]
            cleaned_lines.append(line)
        
        # 去重（基于URL）
        unique_lines = []
        seen_urls = set()
        
        for line in cleaned_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                url = url.strip()
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_lines.append(line)
        
        logger.info(f"清理后链接数: {len(unique_lines)} (原: {len(lines)})")
        return unique_lines
    
    def process_batch_urls(self, lines: List[str], whitelist: set) -> Tuple[List[str], List[str]]:
        """批量处理URL检测"""
        success_list = []
        failed_list = []
        total = len(lines)
        
        if not lines:
            return success_list, failed_list
        
        logger.info(f"开始检测 {total} 个链接")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            # 准备任务
            futures = {}
            for idx, line in enumerate(lines):
                if ',' in line:
                    name, url = line.split(',', 1)
                    url = url.strip()
                    futures[executor.submit(self.check_url, url)] = (idx, line, url)
            
            # 处理结果
            processed = 0
            success_count = 0
            failed_count = 0
            
            for future in as_completed(futures):
                idx, line, url = futures[future]
                processed += 1
                
                try:
                    elapsed, is_valid = future.result()
                    
                    # 白名单强制通过
                    if url in whitelist:
                        success_list.append(f"0.00ms,{line}")
                        success_count += 1
                    elif is_valid:
                        if elapsed is not None:
                            success_list.append(f"{elapsed:.2f}ms,{line}")
                        else:
                            success_list.append(f"0.00ms,{line}")
                        success_count += 1
                    else:
                        failed_list.append(line)
                        failed_count += 1
                    
                    # 进度显示
                    if processed % 50 == 0 or processed == total:
                        logger.info(f"进度: {processed}/{total} | 成功: {success_count} | 失败: {failed_count}")
                        
                except Exception as e:
                    logger.error(f"处理链接失败 {line}: {e}")
                    failed_list.append(line)
                    failed_count += 1
        
        # 按响应时间排序
        success_list.sort(key=lambda x: float(x.split(',')[0].replace('ms', '')))
        
        logger.info(f"检测完成 - 成功: {success_count}, 失败: {failed_count}")
        return success_list, failed_list
    
    def analyze_blacklist(self):
        """分析黑名单数据"""
        if not self.blacklist_dict:
            return
        
        logger.info("黑名单分析:")
        for host, count in sorted(self.blacklist_dict.items(), key=lambda x: x[1], reverse=True)[:10]:
            logger.info(f"  {host}: {count} 次失败")
    
    def run(self):
        """主运行函数"""
        file_paths = self.get_file_paths()
        
        # 1. 获取远程URL
        remote_urls = self.read_txt_to_array(file_paths["urls"])
        all_lines = self.fetch_remote_urls(remote_urls)
        
        # 2. 读取本地白名单
        whitelist_lines = self.read_txt_file(file_paths.get("whitelist_manual", ""))
        whitelist_lines = self.clean_and_deduplicate(whitelist_lines)
        
        # 构建白名单集合
        whitelist_set = set()
        for line in whitelist_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                whitelist_set.add(url.strip())
        
        logger.info(f"白名单链接数: {len(whitelist_set)}")
        
        # 3. 清理和去重所有链接
        cleaned_lines = self.clean_and_deduplicate(all_lines)
        
        # 4. 批量检测
        success_list, failed_list = self.process_batch_urls(cleaned_lines, whitelist_set)
        
        # 5. 保存结果
        self.save_results(success_list, failed_list)
        
        # 6. 分析黑名单
        self.analyze_blacklist()
        
        # 7. 保存缓存
        self.save_cache()
        
        # 8. 输出统计信息
        self.print_statistics(cleaned_lines, success_list, failed_list)
    
    def get_file_paths(self):
        """获取文件路径"""
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        parent2_dir = os.path.dirname(parent_dir)
        
        return {
            "urls": os.path.join(parent_dir, 'urls.txt'),
            "live": os.path.join(parent2_dir, 'live.txt'),
            "blacklist_auto": os.path.join(current_dir, 'blacklist_auto.txt'),
            "whitelist_manual": os.path.join(current_dir, 'whitelist_manual.txt'),
            "whitelist_auto": os.path.join(current_dir, 'whitelist_auto.txt'),
            "whitelist_auto_tv": os.path.join(current_dir, 'whitelist_auto_tv.txt')
        }
    
    def save_results(self, success_list: List[str], failed_list: List[str]):
        """保存检测结果"""
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"
        
        # 准备成功列表（带响应时间）
        success_output = [
            "更新时间,#genre#",
            version,
            "",
            "RespoTime,whitelist,#genre#"
        ] + success_list
        
        # 准备成功列表（无响应时间，用于TV）
        success_tv = [",".join(line.split(",")[1:]) for line in success_list]
        success_tv_output = [
            "更新时间,#genre#",
            version,
            "",
            "whitelist,#genre#"
        ] + success_tv
        
        # 准备失败列表
        failed_output = [
            "更新时间,#genre#",
            version,
            "",
            "blacklist,#genre#"
        ] + failed_list
        
        # 保存文件
        file_paths = self.get_file_paths()
        self.write_list(file_paths["whitelist_auto"], success_output)
        self.write_list(file_paths["whitelist_auto_tv"], success_tv_output)
        self.write_list(file_paths["blacklist_auto"], failed_output)
    
    def write_list(self, file_path: str, data_list: List[str]):
        """写入列表到文件"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8', newline='\n') as f:
                f.write('\n'.join(data_list))
            logger.info(f"文件已生成: {file_path} ({len(data_list)} 行)")
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")
    
    def print_statistics(self, cleaned_lines: List[str], success_list: List[str], failed_list: List[str]):
        """打印统计信息"""
        end_time = datetime.now()
        elapsed = end_time - self.timestart
        mins, secs = int(elapsed.total_seconds() // 60), int(elapsed.total_seconds() % 60)
        
        logger.info("=" * 60)
        logger.info("检测统计:")
        logger.info(f"  总耗时: {mins}分{secs}秒")
        logger.info(f"  原始链接数: {len(self.url_statistics)}")
        logger.info(f"  清理后链接数: {len(cleaned_lines)}")
        logger.info(f"  成功链接数: {len(success_list)}")
        logger.info(f"  失败链接数: {len(failed_list)}")
        
        if cleaned_lines:
            success_rate = len(success_list) / len(cleaned_lines) * 100
            logger.info(f"  成功率: {success_rate:.1f}%")
        
        logger.info("=" * 60)
        
        # 输出来源统计
        if self.url_statistics:
            logger.info("来源统计:")
            for stat in self.url_statistics:
                logger.info(f"  {stat}")

def main():
    """主函数"""
    logger.info("开始直播源检测...")
    checker = StreamChecker()
    
    try:
        checker.run()
    except KeyboardInterrupt:
        logger.info("检测被用户中断")
    except Exception as e:
        logger.error(f"检测过程发生错误: {e}", exc_info=True)
    finally:
        logger.info("检测结束")

if __name__ == "__main__":
    main()
