import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime, timedelta, timezone
import os
from urllib.parse import urlparse, quote, unquote
import socket
import json
import ssl
import re
from typing import List, Tuple, Optional, Dict, Any, Set
import logging
from collections import defaultdict
import statistics

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
    TIMEOUT_FETCH = 10          # 远程URL内容获取超时
    TIMEOUT_CHECK = 5           # 每个直播源检测超时
    TIMEOUT_CONNECT = 3         # 连接建立超时
    TIMEOUT_READ = 2            # 数据读取超时
    
    # 线程配置
    MAX_WORKERS = 30
    
    # 重试配置
    MAX_RETRIES = 0             # 重试次数（0表示不重试）
    RETRY_DELAY = 1             # 重试等待（秒）
    
    # 域名评估配置
    MIN_SUCCESS_RATE = 0.8      # 最低成功率（优秀域名）
    MIN_SAMPLES = 3             # 最少样本数
    MAX_RESPONSE_TIME = 2000    # 最大响应时间(ms)
    
    # 检测策略
    ENABLE_SMART_DETECTION = True  # 启用智能检测
    SKIP_TIMEOUT_URLS = False      # 是否跳过超时URL（False表示超时算失败）


class DomainAnalyzer:
    """域名分析器"""
    def __init__(self):
        self.domain_stats: Dict[str, Dict] = defaultdict(lambda: {
            'success_count': 0,
            'total_count': 0,
            'response_times': [],
            'urls': set(),
            'last_check': None,
            'timeout_count': 0
        })
        self.excellent_domains: Set[str] = set()
        self.good_domains: Set[str] = set()
        self.poor_domains: Set[str] = set()
        self.unstable_domains: Set[str] = set()  # 超时率高的不稳定域名
    
    def record_domain_result(self, domain: str, url: str, success: Optional[bool], 
                           response_time: Optional[float], timeout: bool = False):
        """记录域名检测结果"""
        if not domain:
            return
            
        stats = self.domain_stats[domain]
        stats['total_count'] += 1
        stats['urls'].add(url)
        
        if success is True:
            stats['success_count'] += 1
            if response_time:
                stats['response_times'].append(response_time)
        elif timeout:
            stats['timeout_count'] += 1
        
        stats['last_check'] = datetime.now().isoformat()
    
    def calculate_domain_score(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """计算域名质量分数"""
        stats = self.domain_stats[domain]
        
        if stats['total_count'] < Config.MIN_SAMPLES:
            return 0.0, {'reason': '样本不足'}
        
        # 计算成功率（排除超时）
        valid_checks = stats['total_count'] - stats['timeout_count']
        if valid_checks == 0:
            return 0.0, {'reason': '无有效检测'}
        
        success_rate = stats['success_count'] / valid_checks if valid_checks > 0 else 0
        
        # 计算超时率
        timeout_rate = stats['timeout_count'] / stats['total_count'] if stats['total_count'] > 0 else 0
        
        # 计算平均响应时间
        avg_response = 0
        if stats['response_times']:
            avg_response = statistics.mean(stats['response_times'])
        
        # 计算稳定性（响应时间标准差）
        stability = 1.0
        if len(stats['response_times']) > 1:
            std_dev = statistics.stdev(stats['response_times'])
            stability = max(0, 1 - (std_dev / 1000))
        
        # 计算覆盖率（URL数量）
        url_coverage = min(1.0, len(stats['urls']) / 20)
        
        # 超时惩罚
        timeout_penalty = timeout_rate * 0.3  # 超时率高的域名扣分
        
        # 综合评分
        score = (
            success_rate * 0.5 +          # 成功率权重50%
            (1 - min(1, avg_response / Config.MAX_RESPONSE_TIME)) * 0.2 +  # 速度权重20%
            stability * 0.15 +            # 稳定性权重15%
            url_coverage * 0.1 -          # 覆盖率权重10%
            timeout_penalty               # 超时惩罚
        )
        
        # 确保分数在0-1之间
        score = max(0, min(1, score))
        
        metrics = {
            'success_rate': success_rate,
            'timeout_rate': timeout_rate,
            'avg_response': avg_response,
            'stability': stability,
            'url_count': len(stats['urls']),
            'total_checks': stats['total_count'],
            'timeout_checks': stats['timeout_count']
        }
        
        return score, metrics
    
    def classify_domains(self):
        """分类域名质量"""
        self.excellent_domains.clear()
        self.good_domains.clear()
        self.poor_domains.clear()
        self.unstable_domains.clear()
        
        for domain in self.domain_stats.keys():
            score, metrics = self.calculate_domain_score(domain)
            
            # 超时率超过30%标记为不稳定
            if metrics['timeout_rate'] > 0.3:
                self.unstable_domains.add(domain)
            
            if score >= 0.8:
                self.excellent_domains.add(domain)
            elif score >= 0.6:
                self.good_domains.add(domain)
            else:
                self.poor_domains.add(domain)
    
    def get_excellent_domains_report(self) -> List[Dict[str, Any]]:
        """获取优秀域名报告"""
        report = []
        for domain in self.excellent_domains:
            score, metrics = self.calculate_domain_score(domain)
            report.append({
                'domain': domain,
                'score': round(score, 3),
                'success_rate': round(metrics['success_rate'] * 100, 1),
                'timeout_rate': round(metrics['timeout_rate'] * 100, 1),
                'avg_response': round(metrics['avg_response'], 1),
                'url_count': metrics['url_count'],
                'total_checks': metrics['total_checks']
            })
        
        # 按分数排序
        report.sort(key=lambda x: x['score'], reverse=True)
        return report
    
    def save_domain_analysis(self, filepath: str):
        """保存域名分析结果"""
        analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'excellent_domains': list(self.excellent_domains),
            'good_domains': list(self.good_domains),
            'poor_domains': list(self.poor_domains),
            'unstable_domains': list(self.unstable_domains),
            'detailed_stats': {
                domain: {
                    'success_count': stats['success_count'],
                    'total_count': stats['total_count'],
                    'timeout_count': stats['timeout_count'],
                    'success_rate': round(stats['success_count'] / max(1, stats['total_count'] - stats['timeout_count']) * 100, 1),
                    'timeout_rate': round(stats['timeout_count'] / stats['total_count'] * 100, 1) if stats['total_count'] > 0 else 0,
                    'avg_response': round(statistics.mean(stats['response_times']), 2) if stats['response_times'] else 0,
                    'url_count': len(stats['urls']),
                    'sample_urls': list(stats['urls'])[:3]
                }
                for domain, stats in self.domain_stats.items()
                if stats['total_count'] >= Config.MIN_SAMPLES
            }
        }
        
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(analysis_data, f, ensure_ascii=False, indent=2)
            logger.info(f"域名分析结果已保存到: {filepath}")
        except Exception as e:
            logger.error(f"保存域名分析结果失败: {e}")


class StreamChecker:
    def __init__(self):
        self.timestart = datetime.now()
        self.url_statistics: List[str] = []
        self.domain_analyzer = DomainAnalyzer()
        
        # 域名级缓存（用于智能检测）
        self.domain_quality_cache: Dict[str, float] = {}  # 域名: 质量分数
        self.domain_last_check: Dict[str, datetime] = {}  # 域名: 最后检测时间
    
    def get_domain_from_url(self, url: str) -> str:
        """从URL提取域名"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            if ':' in host:
                if host.startswith('[') and ']' in host:
                    ipv6_end = host.find(']')
                    if ipv6_end != -1 and ':' in host[ipv6_end:]:
                        host = host[:ipv6_end + 1]
                else:
                    host = host.split(':')[0]
            
            return host.lower()
        except:
            return ""
    
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
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = []
                for line in file:
                    line = line.strip()
                    if line and '://' in line and ',' in line and '#genre#' not in line:
                        lines.append(line)
                return lines
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {e}")
            return []
    
    def create_ssl_context(self):
        """创建SSL上下文"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_ciphers('DEFAULT:@SECLEVEL=1')
        return context
    
    def check_http_url(self, url: str, timeout: int) -> Tuple[Optional[bool], Optional[float]]:
        """HTTP/HTTPS检测，返回(状态, 响应时间ms)"""
        start_time = time.time()
        
        for retry in range(Config.MAX_RETRIES + 1):
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
                
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=self.create_ssl_context())
                )
                
                with opener.open(req, timeout=timeout) as resp:
                    if 200 <= resp.status < 300:
                        # 尝试读取少量数据验证
                        resp.read(512)
                        elapsed = (time.time() - start_time) * 1000
                        return True, elapsed
                    elapsed = (time.time() - start_time) * 1000
                    return False, elapsed
                    
            except urllib.error.HTTPError as e:
                elapsed = (time.time() - start_time) * 1000
                if e.code in [401, 403, 404]:
                    return False, elapsed
                # 其他HTTP错误，根据重试次数决定
                if retry == Config.MAX_RETRIES:
                    return None, elapsed  # 重试次数用完，返回未知
                time.sleep(Config.RETRY_DELAY)
                
            except (socket.timeout, urllib.error.URLError) as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    # 判断是超时还是其他错误
                    if isinstance(e, socket.timeout):
                        return None, elapsed  # 超时
                    else:
                        return False, elapsed  # 其他URL错误
                time.sleep(Config.RETRY_DELAY)
                
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    logger.debug(f"HTTP检测异常 {url}: {e}")
                    return False, elapsed
                time.sleep(Config.RETRY_DELAY)
        
        return None, None
    
    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> Tuple[Optional[bool], Optional[float]]:
        """RTMP/RTSP检测，返回(状态, 响应时间ms)"""
        start_time = time.time()
        
        for retry in range(Config.MAX_RETRIES + 1):
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or (1935 if url.startswith('rtmp') else 554)
                
                if not host:
                    elapsed = (time.time() - start_time) * 1000
                    return False, elapsed
                
                # 创建socket连接
                sock = socket.create_connection((host, port), timeout=min(Config.TIMEOUT_CONNECT, timeout))
                
                # 尝试发送简单的协议握手
                if url.startswith('rtmp'):
                    # RTMP简单握手尝试
                    sock.send(b'\x03')
                    sock.settimeout(2)
                    try:
                        data = sock.recv(1)
                        if data:
                            sock.close()
                            elapsed = (time.time() - start_time) * 1000
                            return True, elapsed
                    except socket.timeout:
                        pass
                
                elif url.startswith('rtsp'):
                    # RTSP OPTIONS请求
                    request = f"OPTIONS {url} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {Config.USER_AGENT}\r\n\r\n"
                    sock.send(request.encode())
                    sock.settimeout(2)
                    try:
                        response = sock.recv(1024)
                        if b'RTSP/1.0' in response:
                            sock.close()
                            elapsed = (time.time() - start_time) * 1000
                            return True, elapsed
                    except socket.timeout:
                        pass
                
                sock.close()
                elapsed = (time.time() - start_time) * 1000
                return True, elapsed  # 连接成功就算可用
                
            except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    if isinstance(e, socket.timeout):
                        return None, elapsed  # 超时
                    else:
                        return False, elapsed  # 连接拒绝
                time.sleep(Config.RETRY_DELAY)
                
            except Exception as e:
                elapsed = (time.time() - start_time) * 1000
                if retry == Config.MAX_RETRIES:
                    logger.debug(f"RTMP/RTSP检测异常 {url}: {e}")
                    return False, elapsed
                time.sleep(Config.RETRY_DELAY)
        
        return None, None
    
    def check_url(self, url: str) -> Tuple[Optional[float], Optional[bool]]:
        """
        主检测函数
        返回: (响应时间ms, 状态)
        状态: True=可用, False=不可用, None=超时/未知
        """
        domain = self.get_domain_from_url(url)
        
        # 智能检测：如果域名质量很差，可以快速失败
        if Config.ENABLE_SMART_DETECTION and domain:
            if domain in self.domain_analyzer.unstable_domains:
                # 不稳定域名，设置更短的超时
                check_timeout = min(Config.TIMEOUT_CHECK, 2)
            else:
                check_timeout = Config.TIMEOUT_CHECK
        else:
            check_timeout = Config.TIMEOUT_CHECK
        
        start_time = time.time()
        status = None
        response_time = None
        
        try:
            encoded_url = quote(unquote(url), safe=':/?&=#')
            
            if url.startswith(("http://", "https://")):
                status, response_time = self.check_http_url(encoded_url, check_timeout)
            elif url.startswith(("rtmp://", "rtsp://")):
                status, response_time = self.check_rtmp_rtsp_url(encoded_url, check_timeout)
            else:
                # 其他协议尝试TCP连接
                parsed = urlparse(url)
                host, port = parsed.hostname, parsed.port or 80
                if host:
                    try:
                        sock = socket.create_connection((host, port), timeout=Config.TIMEOUT_CONNECT)
                        sock.close()
                        response_time = (time.time() - start_time) * 1000
                        status = True
                    except Exception:
                        response_time = (time.time() - start_time) * 1000
                        status = False
        
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            logger.debug(f"检测异常 {url}: {e}")
            status = False
        
        # 记录域名统计（区分超时）
        timeout = (status is None)
        if domain:
            self.domain_analyzer.record_domain_result(
                domain, url, status, response_time, timeout
            )
        
        return response_time, status
    
    def process_m3u_content(self, text: str, source_url: str) -> List[str]:
        """处理M3U格式内容"""
        lines = []
        try:
            if "#EXTM3U" not in text:
                return lines
            
            current_name = ""
            for line in text.split('\n'):
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith("#EXTINF"):
                    match = re.search(r',(.+)$', line)
                    if match:
                        current_name = match.group(1).strip()
                elif line.startswith(('http://', 'https://', 'rtmp://', 'rtsp://')):
                    if current_name:
                        lines.append(f"{current_name},{line}")
                    else:
                        lines.append(f"Unknown,{line}")
            
            return lines
            
        except Exception as e:
            logger.error(f"解析M3U内容失败: {e}")
            return []
    
    def fetch_remote_urls(self, urls: List[str]):
        """获取远程URL内容"""
        all_lines = []
        
        for url in urls:
            try:
                encoded_url = quote(unquote(url), safe=':/?&=#')
                req = urllib.request.Request(
                    encoded_url,
                    headers={"User-Agent": Config.USER_AGENT_URL}
                )
                
                with urllib.request.urlopen(req, timeout=Config.TIMEOUT_FETCH) as resp:
                    content = resp.read().decode('utf-8', errors='replace')
                    
                    if "#EXTM3U" in content:
                        lines = self.process_m3u_content(content, url)
                    else:
                        lines = []
                        for line in content.split('\n'):
                            line = line.strip()
                            if line and '://' in line and ',' in line and '#genre#' not in line:
                                lines.append(line)
                    
                    count = len(lines)
                    self.url_statistics.append(f"{count},{url}")
                    all_lines.extend(lines)
                    
            except Exception as e:
                logger.error(f"获取远程URL失败 {url}: {e}")
        
        return all_lines
    
    def clean_and_deduplicate(self, lines: List[str]) -> List[str]:
        """清理和去重链接"""
        new_lines = []
        for line in lines:
            if ',' not in line or '://' not in line:
                continue
            
            name, urls = line.split(',', 1)
            name = name.strip()
            
            for url_part in urls.split('#'):
                url_part = url_part.strip()
                if '://' in url_part:
                    # 移除$符号及其后的内容
                    if '$' in url_part:
                        url_part = url_part[:url_part.rfind('$')]
                    new_lines.append(f"{name},{url_part}")
        
        # 去重
        unique_lines = []
        seen_urls = set()
        
        for line in new_lines:
            if ',' in line:
                _, url = line.split(',', 1)
                url = url.strip()
                if url not in seen_urls:
                    seen_urls.add(url)
                    unique_lines.append(line)
        
        return unique_lines
    
    def process_batch_urls(self, lines: List[str], whitelist: set) -> Tuple[List[str], List[str], List[str]]:
        """
        批量处理URL检测
        返回: (成功列表, 失败列表, 超时列表)
        """
        success_list = []
        failed_list = []
        timeout_list = []
        total = len(lines)
        
        if not lines:
            return success_list, failed_list, timeout_list
        
        logger.info(f"开始检测 {total} 个链接")
        
        with ThreadPoolExecutor(max_workers=Config.MAX_WORKERS) as executor:
            futures = {}
            for idx, line in enumerate(lines):
                if ',' in line:
                    name, url = line.split(',', 1)
                    url = url.strip()
                    futures[executor.submit(self.check_url, url)] = (idx, line, url)
            
            processed = 0
            success_count = 0
            timeout_count = 0
            
            for future in as_completed(futures):
                idx, line, url = futures[future]
                processed += 1
                
                try:
                    response_time, status = future.result()
                    
                    # 白名单强制成功
                    if url in whitelist:
                        elapsed_str = f"{response_time or 0:.2f}ms" if response_time else "0.00ms"
                        success_list.append(f"{elapsed_str},{line}")
                        success_count += 1
                        continue
                    
                    if status is True:
                        # 可用
                        elapsed_str = f"{response_time:.2f}ms" if response_time else "0.00ms"
                        success_list.append(f"{elapsed_str},{line}")
                        success_count += 1
                    elif status is False:
                        # 不可用
                        failed_list.append(line)
                    elif status is None:
                        # 超时/未知
                        timeout_list.append(line)
                        timeout_count += 1
                        # 根据配置决定超时的处理方式
                        if not Config.SKIP_TIMEOUT_URLS:
                            # 超时算失败
                            failed_list.append(line)
                        # 如果SKIP_TIMEOUT_URLS为True，则超时URL不会进入任何列表
                    
                    if processed % 50 == 0 or processed == total:
                        logger.info(f"进度: {processed}/{total} | 成功: {success_count} | 超时: {timeout_count}")
                        
                except Exception as e:
                    logger.error(f"处理链接失败 {line}: {e}")
                    failed_list.append(line)
        
        # 按响应时间排序成功列表
        success_list.sort(key=lambda x: float(x.split(',')[0].replace('ms', '')))
        
        logger.info(f"检测完成 - 成功: {len(success_list)}, 失败: {len(failed_list)}, 超时: {len(timeout_list)}")
        return success_list, failed_list, timeout_list
    
    def print_excellent_domains_report(self):
        """打印优秀域名报告"""
        # 分类域名
        self.domain_analyzer.classify_domains()
        
        # 获取优秀域名报告
        excellent_report = self.domain_analyzer.get_excellent_domains_report()
        
        if not excellent_report:
            logger.info("未找到优秀的域名")
            return
        
        logger.info("=" * 80)
        logger.info("优秀域名排行榜 (基于成功率、速度和稳定性)")
        logger.info("=" * 80)
        logger.info(f"{'排名':<4} {'域名':<40} {'综合评分':<8} {'成功率':<8} {'超时率':<8} {'平均响应':<10}")
        logger.info("-" * 80)
        
        for idx, domain_info in enumerate(excellent_report[:20], 1):
            logger.info(
                f"{idx:<4} {domain_info['domain'][:38]:<40} "
                f"{domain_info['score']:<8.3f} "
                f"{domain_info['success_rate']:<7.1f}% "
                f"{domain_info['timeout_rate']:<7.1f}% "
                f"{domain_info['avg_response']:<9.1f}ms"
            )
        
        logger.info("=" * 80)
        
        # 详细统计
        total_domains = len(self.domain_analyzer.domain_stats)
        excellent_count = len(self.domain_analyzer.excellent_domains)
        good_count = len(self.domain_analyzer.good_domains)
        unstable_count = len(self.domain_analyzer.unstable_domains)
        
        logger.info("域名质量统计:")
        logger.info(f"  总域名数: {total_domains}")
        logger.info(f"  优秀域名: {excellent_count} ({excellent_count/max(1, total_domains)*100:.1f}%)")
        logger.info(f"  良好域名: {good_count} ({good_count/max(1, total_domains)*100:.1f}%)")
        logger.info(f"  较差域名: {total_domains - excellent_count - good_count} ({(total_domains - excellent_count - good_count)/max(1, total_domains)*100:.1f}%)")
        logger.info(f"  不稳定域名: {unstable_count} ({unstable_count/max(1, total_domains)*100:.1f}%)")
        
        # 保存域名分析结果
        self.domain_analyzer.save_domain_analysis("domain_analysis.json")
        
        # 生成优秀域名配置文件
        self.generate_excellent_domains_config()
    
    def generate_excellent_domains_config(self):
        """生成优秀域名配置文件"""
        excellent_domains = self.domain_analyzer.excellent_domains
        
        if not excellent_domains:
            return
        
        # 1. 生成优秀域名列表
        domains_list = sorted(excellent_domains)
        domains_content = "# 优秀域名列表 (自动生成)\n"
        domains_content += f"# 更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        domains_content += f"# 生成规则: 成功率>80%，响应时间<2000ms，超时率<30%\n\n"
        
        for domain in domains_list:
            stats = self.domain_analyzer.domain_stats[domain]
            valid_checks = stats['total_count'] - stats['timeout_count']
            success_rate = stats['success_count'] / valid_checks if valid_checks > 0 else 0
            timeout_rate = stats['timeout_count'] / stats['total_count'] if stats['total_count'] > 0 else 0
            
            avg_response = 0
            if stats['response_times']:
                avg_response = statistics.mean(stats['response_times'])
            
            domains_content += f"# 成功率: {success_rate*100:.1f}% | "
            domains_content += f"超时率: {timeout_rate*100:.1f}% | "
            domains_content += f"平均响应: {avg_response:.1f}ms | "
            domains_content += f"URL数量: {len(stats['urls'])}\n"
            domains_content += f"{domain}\n\n"
        
        # 2. 生成域名过滤规则
        rules_content = "# 域名过滤规则 (用于其他工具)\n"
        rules_content += "# 格式: *域名* 表示匹配该域名的所有子域名\n\n"
        
        all_domains = list(self.domain_analyzer.excellent_domains) + \
                     list(self.domain_analyzer.good_domains)
        
        # 按成功率排序
        sorted_domains = sorted(
            all_domains,
            key=lambda x: self.domain_analyzer.domain_stats[x]['success_count'] / 
                         max(1, self.domain_analyzer.domain_stats[x]['total_count'] - 
                             self.domain_analyzer.domain_stats[x]['timeout_count']),
            reverse=True
        )
        
        for domain in sorted_domains[:100]:  # 前100名
            stats = self.domain_analyzer.domain_stats[domain]
            valid_checks = stats['total_count'] - stats['timeout_count']
            success_rate = stats['success_count'] / valid_checks if valid_checks > 0 else 0
            
            rules_content += f"# 成功率: {success_rate*100:.1f}% "
            rules_content += f"({stats['success_count']}/{valid_checks})\n"
            rules_content += f"*{domain}*\n\n"
        
        # 保存文件
        try:
            with open("excellent_domains.txt", "w", encoding="utf-8") as f:
                f.write(domains_content)
            
            with open("domain_filter_rules.txt", "w", encoding="utf-8") as f:
                f.write(rules_content)
            
            logger.info(f"已生成优秀域名配置文件: excellent_domains.txt ({len(domains_list)}个域名)")
            logger.info(f"已生成域名筛选规则: domain_filter_rules.txt")
            
        except Exception as e:
            logger.error(f"生成配置文件失败: {e}")
    
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
        logger.info(f"清理去重后链接数: {len(cleaned_lines)}")
        
        # 4. 批量检测
        success_list, failed_list, timeout_list = self.process_batch_urls(cleaned_lines, whitelist_set)
        
        # 5. 分析并显示优秀域名
        self.print_excellent_domains_report()
        
        # 6. 保存结果
        self.save_results(success_list, failed_list, timeout_list)
        
        # 7. 输出统计信息
        self.print_statistics(cleaned_lines, success_list, failed_list, timeout_list)
    
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
    
    def save_results(self, success_list: List[str], failed_list: List[str], timeout_list: List[str]):
        """保存检测结果"""
        bj_time = datetime.now(timezone.utc) + timedelta(hours=8)
        version = f"{bj_time.strftime('%Y%m%d %H:%M')},url"
        
        # 准备成功列表
        success_output = [
            "更新时间,#genre#",
            version,
            "",
            "RespoTime,whitelist,#genre#"
        ] + success_list
        
        # 准备成功列表（无响应时间）
        success_tv = [",".join(line.split(",")[1:]) for line in success_list]
        success_tv_output = [
            "更新时间,#genre#",
            version,
            "",
            "whitelist,#genre#"
        ] + success_tv
        
        # 准备失败列表（包括超时的，根据配置）
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
        
        # 保存超时列表到单独文件（如果需要）
        if timeout_list and Config.SKIP_TIMEOUT_URLS:
            timeout_output = [
                "更新时间,#genre#",
                version,
                "",
                "timeout,#genre#"
            ] + timeout_list
            self.write_list("timeout_list.txt", timeout_output)
            logger.info(f"超时链接已保存到: timeout_list.txt ({len(timeout_list)}个)")
    
    def write_list(self, file_path: str, data_list: List[str]):
        """写入列表到文件"""
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data_list))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")
    
    def print_statistics(self, cleaned_lines: List[str], success_list: List[str], 
                        failed_list: List[str], timeout_list: List[str]):
        """打印统计信息"""
        end_time = datetime.now()
        elapsed = end_time - self.timestart
        mins, secs = int(elapsed.total_seconds() // 60), int(elapsed.total_seconds() % 60)
        
        total_detected = len(success_list) + len(failed_list)
        if Config.SKIP_TIMEOUT_URLS:
            total_detected += len(timeout_list)
        
        logger.info("=" * 60)
        logger.info("最终统计:")
        logger.info(f"  总耗时: {mins}分{secs}秒")
        logger.info(f"  清理后链接数: {len(cleaned_lines)}")
        logger.info(f"  检测链接数: {total_detected}")
        logger.info(f"  成功链接数: {len(success_list)}")
        logger.info(f"  失败链接数: {len(failed_list)}")
        logger.info(f"  超时链接数: {len(timeout_list)}")
        
        if total_detected > 0:
            success_rate = len(success_list) / total_detected * 100
            logger.info(f"  整体成功率: {success_rate:.1f}%")
            
            if timeout_list:
                timeout_rate = len(timeout_list) / total_detected * 100
                logger.info(f"  超时率: {timeout_rate:.1f}%")
        
        # 显示最快的5个和最慢的5个链接
        if success_list:
            sorted_success = sorted(success_list, 
                                  key=lambda x: float(x.split(',')[0].replace('ms', '')))
            
            logger.info(f"  最快5个链接:")
            for i, link in enumerate(sorted_success[:5]):
                parts = link.split(',', 1)
                time_str = parts[0]
                name = parts[1].split(',')[0] if ',' in parts[1] else "Unknown"
                logger.info(f"    {i+1}. {time_str} - {name[:30]}")
            
            logger.info(f"  最慢5个链接:")
            for i, link in enumerate(sorted_success[-5:][::-1]):
                parts = link.split(',', 1)
                time_str = parts[0]
                name = parts[1].split(',')[0] if ',' in parts[1] else "Unknown"
                logger.info(f"    {i+1}. {time_str} - {name[:30]}")
        
        logger.info("=" * 60)


def main():
    """主函数"""
    logger.info("开始直播源检测和域名质量分析...")
    logger.info(f"配置: 超时={Config.TIMEOUT_CHECK}s, 线程={Config.MAX_WORKERS}, 重试={Config.MAX_RETRIES}")
    logger.info(f"超时处理: {'跳过' if Config.SKIP_TIMEOUT_URLS else '算作失败'}")
    
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
