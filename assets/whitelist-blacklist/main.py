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
from typing import List, Tuple, Optional, Dict, Any, Set
import logging
import hashlib
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
    # 远程URL内容超时
    TIMEOUT_FETCH = 10
    # 每个直播源超时
    TIMEOUT_CHECK = 8
    # 只控制建立连接的时间，不包括数据传输超时
    TIMEOUT_CONNECT = 5
    
    # 线程配置
    MAX_WORKERS = 30
    
    # 重试配置
    # 重试次数
    MAX_RETRIES = 0
    # 重试等待（秒）
    RETRY_DELAY = 1
    
    # 域名评估配置
    MIN_SUCCESS_RATE = 0.8      # 最低成功率（优秀域名）
    MIN_SAMPLES = 3             # 最少样本数
    MAX_RESPONSE_TIME = 2000    # 最大响应时间(ms)
    
    # 缓存配置
    CACHE_EXPIRE_HOURS = 24

class DomainAnalyzer:
    """域名分析器"""
    def __init__(self):
        self.domain_stats: Dict[str, Dict] = defaultdict(lambda: {
            'success_count': 0,
            'total_count': 0,
            'response_times': [],
            'urls': set(),
            'last_check': None
        })
        self.excellent_domains: Set[str] = set()
        self.good_domains: Set[str] = set()
        self.poor_domains: Set[str] = set()
    
    def record_domain_result(self, domain: str, url: str, success: bool, response_time: Optional[float]):
        """记录域名检测结果"""
        if not domain:
            return
            
        stats = self.domain_stats[domain]
        stats['total_count'] += 1
        stats['urls'].add(url)
        
        if success:
            stats['success_count'] += 1
            if response_time:
                stats['response_times'].append(response_time)
        
        stats['last_check'] = datetime.now().isoformat()
    
    def calculate_domain_score(self, domain: str) -> Tuple[float, Dict[str, Any]]:
        """计算域名质量分数"""
        stats = self.domain_stats[domain]
        
        if stats['total_count'] < Config.MIN_SAMPLES:
            return 0.0, {'reason': '样本不足'}
        
        # 计算成功率
        success_rate = stats['success_count'] / stats['total_count']
        
        # 计算平均响应时间
        avg_response = 0
        if stats['response_times']:
            avg_response = statistics.mean(stats['response_times'])
        
        # 计算稳定性（响应时间标准差）
        stability = 1.0
        if len(stats['response_times']) > 1:
            std_dev = statistics.stdev(stats['response_times'])
            # 标准差越小越好，归一化到0-1
            stability = max(0, 1 - (std_dev / 1000))
        
        # 计算覆盖率（URL数量）
        url_coverage = min(1.0, len(stats['urls']) / 20)  # 最多20个URL得满分
        
        # 综合评分
        score = (
            success_rate * 0.5 +          # 成功率权重50%
            (1 - min(1, avg_response / Config.MAX_RESPONSE_TIME)) * 0.3 +  # 速度权重30%
            stability * 0.1 +             # 稳定性权重10%
            url_coverage * 0.1            # 覆盖率权重10%
        )
        
        metrics = {
            'success_rate': success_rate,
            'avg_response': avg_response,
            'stability': stability,
            'url_count': len(stats['urls']),
            'total_checks': stats['total_count']
        }
        
        return score, metrics
    
    def classify_domains(self):
        """分类域名质量"""
        self.excellent_domains.clear()
        self.good_domains.clear()
        self.poor_domains.clear()
        
        for domain in self.domain_stats.keys():
            score, metrics = self.calculate_domain_score(domain)
            
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
            'detailed_stats': {
                domain: {
                    'success_count': stats['success_count'],
                    'total_count': stats['total_count'],
                    'success_rate': round(stats['success_count'] / stats['total_count'] * 100, 1),
                    'avg_response': round(statistics.mean(stats['response_times']), 2) if stats['response_times'] else 0,
                    'url_count': len(stats['urls']),
                    'sample_urls': list(stats['urls'])[:3]  # 只保存前3个示例URL
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
        self.success_cache: Dict[str, Tuple[float, datetime]] = {}
        self.failed_cache: Dict[str, datetime] = {}
        self.domain_analyzer = DomainAnalyzer()
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
    
    def get_domain_from_url(self, url: str) -> str:
        """从URL提取域名"""
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            # 处理端口号
            if ':' in host:
                # IPv6地址处理
                if host.startswith('[') and ']' in host:
                    # IPv6地址格式 [::1]:8080
                    ipv6_end = host.find(']')
                    if ipv6_end != -1 and ':' in host[ipv6_end:]:
                        host = host[:ipv6_end + 1]
                else:
                    # IPv4地址或域名
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
    
    def check_http_url_with_retry(self, url: str, timeout: int) -> Optional[bool]:
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
                
                opener = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=self.create_ssl_context())
                )
                
                with opener.open(req, timeout=timeout) as resp:
                    if 200 <= resp.status < 300:
                        # 尝试读取少量数据验证
                        resp.read(512)
                        return True
                    return False
                    
            except urllib.error.HTTPError as e:
                if e.code in [401, 403, 404]:
                    return False
                if retry == Config.MAX_RETRIES - 1:
                    return None
            except (socket.timeout, urllib.error.URLError):
                if retry == Config.MAX_RETRIES - 1:
                    return None
                time.sleep(Config.RETRY_DELAY)
            except Exception:
                if retry == Config.MAX_RETRIES - 1:
                    return None
                time.sleep(Config.RETRY_DELAY)
        
        return None
    
    def check_rtmp_rtsp_url(self, url: str, timeout: int) -> Optional[bool]:
        """检测RTMP/RTSP链接"""
        for retry in range(Config.MAX_RETRIES):
            try:
                # 简化检测：尝试TCP连接
                parsed = urlparse(url)
                host, port = parsed.hostname, parsed.port or (1935 if url.startswith('rtmp') else 554)
                
                if not host:
                    return False
                
                # 创建socket连接
                sock = socket.create_connection((host, port), timeout=Config.TIMEOUT_CONNECT)
                sock.close()
                return True
                
            except (socket.timeout, ConnectionRefusedError):
                if retry == Config.MAX_RETRIES - 1:
                    return None
                time.sleep(Config.RETRY_DELAY)
            except Exception:
                if retry == Config.MAX_RETRIES - 1:
                    return None
                time.sleep(Config.RETRY_DELAY)
        
        return None
    
    def check_url(self, url: str) -> Tuple[Optional[float], bool]:
        """主检测函数"""
        url_hash = self.get_url_hash(url)
        
        # 检查缓存
        if url_hash in self.success_cache:
            elapsed, cache_time = self.success_cache[url_hash]
            if (datetime.now() - cache_time).total_seconds() < 3600:
                return elapsed, True
        
        if url_hash in self.failed_cache:
            cache_time = self.failed_cache[url_hash]
            if (datetime.now() - cache_time).total_seconds() < 1800:
                return None, False
        
        start_time = time.time()
        result = None
        
        try:
            encoded_url = quote(unquote(url), safe=':/?&=#')
            
            if url.startswith(("http://", "https://")):
                result = self.check_http_url_with_retry(encoded_url, Config.TIMEOUT_CHECK)
            elif url.startswith(("rtmp://", "rtsp://")):
                result = self.check_rtmp_rtsp_url(encoded_url, Config.TIMEOUT_CHECK)
            else:
                # 其他协议尝试TCP连接
                parsed = urlparse(url)
                host, port = parsed.hostname, parsed.port or 80
                if host:
                    socket.create_connection((host, port), timeout=Config.TIMEOUT_CONNECT)
                    result = True
        
        except Exception:
            result = False
        
        elapsed = (time.time() - start_time) * 1000 if result else None
        
        # 更新缓存
        if result is True:
            self.success_cache[url_hash] = (elapsed, datetime.now())
        elif result is False:
            self.failed_cache[url_hash] = datetime.now()
        
        # 记录域名统计
        domain = self.get_domain_from_url(url)
        if domain:
            self.domain_analyzer.record_domain_result(domain, url, result is True, elapsed)
        
        if result is True:
            return elapsed, True
        elif result is False:
            return None, False
        else:
            return elapsed, True  # 超时未知暂时算成功
    
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
                req = urllib.request.Request(
                    url,
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
    
    def process_batch_urls(self, lines: List[str], whitelist: set) -> Tuple[List[str], List[str]]:
        """批量处理URL检测"""
        success_list = []
        failed_list = []
        total = len(lines)
        
        if not lines:
            return success_list, failed_list
        
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
            
            for future in as_completed(futures):
                idx, line, url = futures[future]
                processed += 1
                
                try:
                    elapsed, is_valid = future.result()
                    
                    if url in whitelist or is_valid:
                        if elapsed is not None:
                            success_list.append(f"{elapsed:.2f}ms,{line}")
                        else:
                            success_list.append(f"0.00ms,{line}")
                        success_count += 1
                    else:
                        failed_list.append(line)
                    
                    if processed % 50 == 0 or processed == total:
                        logger.info(f"进度: {processed}/{total} | 成功: {success_count}")
                        
                except Exception as e:
                    logger.error(f"处理链接失败 {line}: {e}")
                    failed_list.append(line)
        
        success_list.sort(key=lambda x: float(x.split(',')[0].replace('ms', '')))
        
        logger.info(f"检测完成 - 成功: {len(success_list)}, 失败: {len(failed_list)}")
        return success_list, failed_list
    
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
        logger.info(f"{'排名':<4} {'域名':<40} {'综合评分':<8} {'成功率':<8} {'平均响应':<10} {'URL数量':<8}")
        logger.info("-" * 80)
        
        for idx, domain_info in enumerate(excellent_report[:20], 1):  # 显示前20名
            logger.info(
                f"{idx:<4} {domain_info['domain'][:38]:<40} "
                f"{domain_info['score']:<8.3f} "
                f"{domain_info['success_rate']:<7.1f}% "
                f"{domain_info['avg_response']:<9.1f}ms "
                f"{domain_info['url_count']:<8}"
            )
        
        logger.info("=" * 80)
        
        # 详细统计
        total_domains = len(self.domain_analyzer.domain_stats)
        excellent_count = len(self.domain_analyzer.excellent_domains)
        good_count = len(self.domain_analyzer.good_domains)
        
        logger.info("域名质量统计:")
        logger.info(f"  总域名数: {total_domains}")
        logger.info(f"  优秀域名: {excellent_count} ({excellent_count/total_domains*100:.1f}%)")
        logger.info(f"  良好域名: {good_count} ({good_count/total_domains*100:.1f}%)")
        logger.info(f"  较差域名: {total_domains - excellent_count - good_count} ({(total_domains - excellent_count - good_count)/total_domains*100:.1f}%)")
        
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
        domains_content = "# 优秀域名列表 (自动生成)\n# 更新时间: {}\n\n".format(
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        
        for domain in domains_list:
            stats = self.domain_analyzer.domain_stats[domain]
            success_rate = stats['success_count'] / stats['total_count'] * 100
            domains_content += f"# {success_rate:.1f}% - {len(stats['urls'])}个URL\n{domain}\n"
        
        # 2. 生成优秀域名筛选规则（可用于其他工具）
        rules_content = "# 优秀域名筛选规则\n"
        rules_content += "# 以下域名在检测中表现优秀，建议优先使用\n\n"
        
        for domain in sorted(excellent_domains, 
                           key=lambda x: self.domain_analyzer.domain_stats[x]['success_count'], 
                           reverse=True)[:50]:  # 前50名
            
            stats = self.domain_analyzer.domain_stats[domain]
            if stats['response_times']:
                avg_time = statistics.mean(stats['response_times'])
            else:
                avg_time = 0
            
            rules_content += (
                f"# {stats['success_count']}/{stats['total_count']} "
                f"({stats['success_count']/stats['total_count']*100:.1f}%) "
                f"- {avg_time:.1f}ms\n"
                f"*{domain}*\n"
            )
        
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
        
        # 4. 批量检测
        success_list, failed_list = self.process_batch_urls(cleaned_lines, whitelist_set)
        
        # 5. 分析并显示优秀域名
        self.print_excellent_domains_report()
        
        # 6. 保存结果
        self.save_results(success_list, failed_list)
        
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
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(data_list))
        except Exception as e:
            logger.error(f"写入文件失败 {file_path}: {e}")
    
    def print_statistics(self, cleaned_lines: List[str], success_list: List[str], failed_list: List[str]):
        """打印统计信息"""
        end_time = datetime.now()
        elapsed = end_time - self.timestart
        mins, secs = int(elapsed.total_seconds() // 60), int(elapsed.total_seconds() % 60)
        
        logger.info("=" * 60)
        logger.info("最终统计:")
        logger.info(f"  总耗时: {mins}分{secs}秒")
        logger.info(f"  清理后链接数: {len(cleaned_lines)}")
        logger.info(f"  成功链接数: {len(success_list)}")
        logger.info(f"  失败链接数: {len(failed_list)}")
        
        if cleaned_lines:
            success_rate = len(success_list) / len(cleaned_lines) * 100
            logger.info(f"  整体成功率: {success_rate:.1f}%")
        
        logger.info("=" * 60)

def main():
    """主函数"""
    logger.info("开始直播源检测和域名质量分析...")
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
