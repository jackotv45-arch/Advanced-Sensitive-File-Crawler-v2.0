#!/usr/bin/env python3
"""
Advanced Sensitive File Crawler v2.1
With Optional JS Rendering & Interactive Menu
"""

import asyncio
import aiohttp
import aiofiles
import hashlib
import random
import string
import time
import json
import re
import os
import sys
from urllib.parse import urljoin, urlparse, quote
from dataclasses import dataclass, field, asdict
from typing import Set, List, Dict, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict
import logging
from datetime import datetime

# Playwright - optional
PLAYWRIGHT_AVAILABLE = False
try:
    from playwright.async_api import async_playwright, Page, Browser
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    pass

# Rich - optional but recommended
RICH_AVAILABLE = False
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.prompt import Prompt, Confirm
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    pass

# Questionary - optional
QUESTIONARY_AVAILABLE = False
try:
    import questionary
    from questionary import Choice
    QUESTIONARY_AVAILABLE = True
except ImportError:
    pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler('crawler.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

console = Console() if RICH_AVAILABLE else None

@dataclass
class CrawlConfig:
    target: str = ""
    max_workers: int = 30
    delay_min: float = 1.0
    delay_max: float = 3.0
    max_depth: int = 2
    use_js: bool = False  # Désactivé par défaut si Playwright pas dispo
    proxy: str = ""
    wordlist_custom: List[str] = field(default_factory=list)
    output_format: str = "json"
    user_agent: str = "random"
    
    CONFIG_FILE = Path.home() / ".sensitive_crawler_config.json"
    
    def save(self):
        with open(self.CONFIG_FILE, 'w') as f:
            json.dump(asdict(self), f, indent=2)
    
    @classmethod
    def load(cls) -> 'CrawlConfig':
        if cls.CONFIG_FILE.exists():
            with open(cls.CONFIG_FILE, 'r') as f:
                data = json.load(f)
                return cls(**data)
        return cls()

@dataclass
class CrawlResult:
    url: str
    status: int
    size: int
    content_hash: str
    is_interesting: bool = False
    findings: List[str] = field(default_factory=list)
    response_time: float = 0.0
    tech_detected: List[str] = field(default_factory=list)
    content_type: str = ""
    discovered_paths: List[str] = field(default_factory=list)

class TechFingerprint:
    SIGNATURES = {
        'wordpress': {
            'headers': ['X-Powered-By: PHP', 'wp-content'],
            'body': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'files': ['wp-config.php', 'wp-login.php', 'xmlrpc.php']
        },
        'laravel': {
            'headers': ['X-Frame-Options: SAMEORIGIN'],
            'body': ['csrf-token', 'laravel_session'],
            'files': ['.env', 'vendor/autoload.php', 'artisan']
        },
        'django': {
            'headers': ['csrftoken', 'django'],
            'body': ['csrfmiddlewaretoken', '__debug__'],
            'files': ['settings.py', 'manage.py', 'db.sqlite3']
        },
        'rails': {
            'headers': ['_session_id', 'X-Runtime'],
            'body': ['csrf-param', 'authenticity_token'],
            'files': ['config/database.yml', 'config/secrets.yml']
        },
        'php': {
            'headers': ['X-Powered-By: PHP'],
            'body': ['<?php', 'phpinfo()'],
            'files': ['phpinfo.php', 'info.php']
        },
        'nodejs': {
            'headers': ['X-Powered-By: Express'],
            'body': ['node_modules', 'package.json'],
            'files': ['package.json', 'server.js']
        }
    }

    @classmethod
    def detect(cls, headers: Dict, body: str) -> List[str]:
        detected = []
        headers_str = ' '.join([f"{k}: {v}" for k, v in headers.items()])
        
        for tech, sigs in cls.SIGNATURES.items():
            score = 0
            for header_sig in sigs['headers']:
                if header_sig.lower() in headers_str.lower():
                    score += 2
            for body_sig in sigs['body']:
                if body_sig in body:
                    score += 3
            if score >= 3:
                detected.append(tech)
        return detected

class WordlistMutator:
    TECH_WORDLISTS = {
        'wordpress': [
            'wp-content/debug.log', 'wp-content/uploads/',
            'wp-admin/install.php', '.maintenance', 'wp-config.php.bak'
        ],
        'laravel': [
            'storage/logs/laravel.log', 'bootstrap/cache/config.php',
            '.env.testing', 'artisan.backup'
        ],
        'django': [
            'static/admin/', 'media/', 'settings/local.py',
            'db.sqlite3.bak', 'fixtures/'
        ],
        'rails': [
            'log/development.log', 'config/master.key',
            'db/development.sqlite3'
        ],
        'php': [
            'composer.lock', 'php_errors.log',
            '.user.ini', 'php.ini.bak'
        ],
        'nodejs': [
            'package-lock.json.bak', '.env.development',
            'npm-debug.log', 'yarn-error.log'
        ]
    }

    def __init__(self, base_wordlist: List[str]):
        self.base = base_wordlist
        self.discovered_paths: Set[str] = set()
        
    def mutate(self, detected_techs: List[str], discovered_dirs: List[str]) -> List[str]:
        mutated = list(self.base)
        
        for tech in detected_techs:
            if tech in self.TECH_WORDLISTS:
                mutated.extend(self.TECH_WORDLISTS[tech])
                
        for directory in discovered_dirs:
            clean_dir = directory.rstrip('/')
            mutated.extend([
                f"{clean_dir}.bak", f"{clean_dir}.old", f"{clean_dir}.zip",
                f"{clean_dir}/backup/", f"{clean_dir}/old/"
            ])
            
        return list(set(mutated))

class JSRenderer:
    """Renderer JS optionnel avec fallback"""
    
    def __init__(self):
        self.browser: Optional[Any] = None
        self.available = PLAYWRIGHT_AVAILABLE
        
    async def init(self):
        if not self.available:
            return False
            
        try:
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-setuid-sandbox']
            )
            return True
        except Exception as e:
            logger.warning(f"Playwright init failed: {e}")
            self.available = False
            return False
        
    async def render(self, url: str) -> Tuple[str, List[str], Dict]:
        if not self.available or not self.browser:
            return "", [], {}
            
        page = await self.browser.new_page()
        
        try:
            response = await page.goto(url, wait_until='networkidle', timeout=30000)
            headers = await response.all_headers() if response else {}
            await asyncio.sleep(2)
            content = await page.content()
            
            # Extraction URLs
            urls = await page.evaluate('''() => {
                const urls = [];
                document.querySelectorAll('script[src]').forEach(s => urls.push(s.src));
                document.querySelectorAll('a[href]').forEach(a => urls.push(a.href));
                document.querySelectorAll('form[action]').forEach(f => urls.push(f.action));
                return [...new Set(urls)];
            }''')
            
            await page.close()
            return content, urls, headers
            
        except Exception as e:
            logger.error(f"JS render error: {e}")
            await page.close()
            return "", [], {}

    async def close(self):
        if self.browser:
            await self.browser.close()

class AdvancedCrawler:
    def __init__(self, target: str, max_workers: int = 30, 
                 delay: Tuple[float, float] = (1.0, 3.0),
                 use_js: bool = False, depth: int = 2):
        
        self.target = target.rstrip('/')
        self.domain = urlparse(target).netloc
        self.max_workers = max_workers
        self.delay = delay
        self.max_depth = depth
        
        # Désactive JS si Playwright pas disponible
        self.use_js = use_js and PLAYWRIGHT_AVAILABLE
        
        if use_js and not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not available, JS rendering disabled")
        
        self.visited: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.error_fingerprints: Dict[int, str] = {}
        self.discovered_dirs: Set[str] = set()
        self.detected_techs: Set[str] = set()
        
        self.mutator = WordlistMutator(self._build_base_wordlist())
        
        self.sensitive_patterns = {
            'api_key': r'\b(?:api[_-]?key|apikey)["\s]*[:=]["\s]*["\'][a-zA-Z0-9]{32,64}["\']',
            'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'private_key': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'db_connection': r'(mongodb|mysql|postgres|redis)://[^"\s<>]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'secret': r'\b(?:secret|password)["\s]*[:=]["\s]*["\'][^"\']+["\']',
            'token': r'\b(?:token|access_token)["\s]*[:=]["\s]*["\'][a-zA-Z0-9_-]+["\']',
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        ]

    def _build_base_wordlist(self) -> List[str]:
        common = [
            '.env', '.env.local', '.env.production', '.env.backup',
            'backup.zip', 'backup.tar.gz', 'www.zip', 'site.zip',
            'dump.sql', 'database.sql', 'db.sql', 'backup.sql',
            '.git/config', '.git/HEAD', '.svn/entries', '.svn/wc.db',
            '.idea/workspace.xml', '.vscode/settings.json',
            'error.log', 'access.log', 'debug.log', 'application.log',
            'config.php', 'config.json', 'config.yaml', 'settings.php',
            'phpinfo.php', 'info.php', 'test.php',
            'api-docs', 'swagger.json', 'openapi.json',
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            '.htaccess', '.htpasswd', 'nginx.conf',
            'composer.lock', 'package-lock.json', 'yarn.lock',
            'id_rsa', 'id_dsa', '.ssh/authorized_keys',
            'server.key', 'private.key', 'cert.pem'
        ]
        
        encoded = []
        for word in common:
            encoded.append(quote(word, safe=''))
            encoded.append(word.replace('/', '%2f'))
            
        return list(set(common + encoded))

    async def _get_session(self) -> aiohttp.ClientSession:
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
        }
        
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False
        )
        
        return aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30, connect=10),
            raise_for_status=False
        )

    def _calculate_entropy(self, data: str) -> float:
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x).bit_length()
        return entropy / 8

    async def _extract_urls(self, content: str, base_url: str) -> List[str]:
        urls = []
        patterns = [
            r'["\'](\/[a-zA-Z0-9_\-\/\.]+\.[a-zA-Z0-9]+)["\']',
            r'url\s*:\s*["\']([^"\']+)["\']',
            r'href\s*=\s*["\']([^"\']+)["\']',
            r'src\s*=\s*["\']([^"\']+)["\']',
            r'\/api\/[a-zA-Z0-9_\-\/]+',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                if match.startswith('http'):
                    urls.append(match)
                elif match.startswith('/'):
                    urls.append(f"{self.target}{match}")
                else:
                    urls.append(urljoin(base_url, match))
                    
        for url in urls:
            parsed = urlparse(url)
            path_parts = parsed.path.split('/')
            for i in range(1, len(path_parts)):
                dir_path = '/'.join(path_parts[:i])
                if dir_path:
                    self.discovered_dirs.add(dir_path)
                    
        return list(set(urls))

    async def _analyze_content(self, url: str, content: bytes, status: int, 
                               headers: Dict, content_type: str = "") -> CrawlResult:
        start_time = time.time()
        size = len(content)
        content_hash = hashlib.md5(content).hexdigest()
        
        text_content = ""
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            pass
            
        techs = TechFingerprint.detect(headers, text_content)
        self.detected_techs.update(techs)
        
        result = CrawlResult(
            url=url, status=status, size=size, content_hash=content_hash,
            tech_detected=techs, content_type=content_type,
            response_time=time.time() - start_time
        )
        
        if status in self.error_fingerprints:
            if content_hash == self.error_fingerprints[status]:
                return result
        
        if text_content:
            entropy = self._calculate_entropy(text_content[:2000])
            if entropy > 0.7:
                result.findings.append(f"High entropy: {entropy:.2f}")
                result.is_interesting = True
        
        for finding_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if matches:
                result.findings.append(f"{finding_type}: {len(matches)} matches")
                result.is_interesting = True
        
        path_lower = urlparse(url).path.lower()
        sensitive_exts = ['.sql', '.env', '.config', '.backup', '.key', '.pem']
        if any(path_lower.endswith(ext) for ext in sensitive_exts):
            result.is_interesting = True
            result.findings.append("Sensitive extension")
            
        if size > 5 * 1024 * 1024:
            result.is_interesting = True
            result.findings.append(f"Large file: {size/1024/1024:.2f}MB")
            
        discovered = await self._extract_urls(text_content, url)
        result.discovered_paths = [u for u in discovered if u not in self.visited]
        
        return result

    async def _fetch(self, session: aiohttp.ClientSession, url: str, 
                     semaphore: asyncio.Semaphore, depth: int = 0) -> Optional[CrawlResult]:
        async with semaphore:
            if url in self.visited or depth > self.max_depth:
                return None
            self.visited.add(url)
            
            await asyncio.sleep(random.uniform(*self.delay))
            
            try:
                async with session.get(url, allow_redirects=True, ssl=False) as response:
                    content = await response.read()
                    ct = response.headers.get('Content-Type', '')
                    
                    result = await self._analyze_content(
                        url, content, response.status, 
                        dict(response.headers), ct
                    )
                    
                    if result.is_interesting:
                        logger.info(f"[HIT] {url} | {response.status} | {result.findings}")
                    
                    if depth < self.max_depth and result.discovered_paths:
                        for new_url in result.discovered_paths:
                            if self.domain in new_url:
                                asyncio.create_task(
                                    self._fetch(session, new_url, semaphore, depth + 1)
                                )
                    
                    return result
                    
            except Exception as e:
                logger.debug(f"Error {url}: {e}")
                
            return None

    async def _calibrate_errors(self, session: aiohttp.ClientSession):
        logger.info("Calibrating error pages...")
        
        for _ in range(3):
            try:
                path = ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
                url = f"{self.target}/{path}"
                async with session.get(url, ssl=False) as response:
                    content = await response.read()
                    self.error_fingerprints[response.status] = hashlib.md5(content).hexdigest()
            except:
                pass

    async def crawl(self) -> List[CrawlResult]:
        session = await self._get_session()
        semaphore = asyncio.Semaphore(self.max_workers)
        
        await self._calibrate_errors(session)
        
        urls_phase1 = [f"{self.target}/{word}" for word in self.mutator.base]
        
        logger.info(f"Phase 1: Testing {len(urls_phase1)} URLs...")
        tasks = [self._fetch(session, url, semaphore, 0) for url in urls_phase1]
        phase1_results = await asyncio.gather(*tasks)
        
        # JS Rendering (si disponible)
        if self.use_js:
            logger.info("Phase 2: JavaScript rendering...")
            renderer = JSRenderer()
            if await renderer.init():
                for path in ['/login', '/admin', '/app']:
                    try:
                        url = f"{self.target}{path}"
                        content, urls, headers = await renderer.render(url)
                        if content:
                            result = await self._analyze_content(url, content.encode(), 200, headers)
                            if result.is_interesting:
                                self.results.append(result)
                    except:
                        pass
                await renderer.close()
        
        # Mutation
        mutated = self.mutator.mutate(list(self.detected_techs), list(self.discovered_dirs))
        new_urls = [f"{self.target}/{w}" for w in mutated if f"{self.target}/{w}" not in self.visited]
        
        if new_urls:
            logger.info(f"Phase 3: Testing {len(new_urls)} mutated URLs...")
            tasks = [self._fetch(session, url, semaphore, 0) for url in new_urls]
            phase3_results = await asyncio.gather(*tasks)
        else:
            phase3_results = []
        
        await session.close()
        
        self.results = [r for r in phase1_results + phase3_results if r is not None]
        return self.results

    def generate_report(self, output_file: str = "crawl_report.json"):
        hits = [r for r in self.results if r.is_interesting]
        
        report = {
            'scan_info': {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'total_tested': len(self.visited),
                'interesting_findings': len(hits),
                'technologies_detected': list(self.detected_techs),
                'js_rendering': self.use_js and PLAYWRIGHT_AVAILABLE
            },
            'findings': [{
                'url': r.url, 'status': r.status, 'size': r.size,
                'findings': r.findings, 'technologies': r.tech_detected
            } for r in hits]
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        # HTML report simple
        html = f"""<!DOCTYPE html>
<html><head><title>Report - {self.target}</title>
<style>
body{{font-family:Arial,sans-serif;margin:40px;background:#1a1a1a;color:#e0e0e0}}
h1,h2{{color:#00ff88}}.finding{{background:#2a2a2a;margin:10px 0;padding:15px;border-radius:8px;border-left:4px solid #ffaa00}}
.url{{font-family:monospace;color:#66ccff;word-break:break-all}}
.CRITICAL{{border-left-color:#ff0044}}.HIGH{{border-left-color:#ff6600}}
</style></head><body>
<h1>🔍 Scan Report: {self.target}</h1>
<p>Total: {len(self.visited)} | Findings: {len(hits)}</p>
{''.join([f'<div class="finding"><div class="url">{r.url}</div><div>{", ".join(r.findings)}</div></div>' for r in hits])}
</body></html>"""
        
        with open(output_file.replace('.json', '.html'), 'w') as f:
            f.write(html)
            
        logger.info(f"Reports saved: {output_file}")
        return report

class InteractiveMenu:
    """Menu interactif avec fallback texte"""
    
    def __init__(self):
        self.config = CrawlConfig.load()
        self.banner = """
╔══════════════════════════════════════════════════════════════════╗
║                    SENSITIVE FILE CRAWLER v2.1                   ║
║                                                                  ║
║  Advanced discovery with optional JavaScript rendering          ║
╚══════════════════════════════════════════════════════════════════╝"""
        
    def clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        if console:
            console.print(Panel(self.banner, border_style="cyan"))
        else:
            print(self.banner)
            
    def input_text(self, prompt: str, default: str = "") -> str:
        if QUESTIONARY_AVAILABLE:
            return questionary.text(prompt, default=default).ask() or default
        return input(f"{prompt} [{default}]: ") or default
        
    def input_select(self, prompt: str, choices: List[Tuple[str, Any]], default: Any = None) -> Any:
        if QUESTIONARY_AVAILABLE:
            q_choices = [Choice(label, value) for label, value in choices]
            return questionary.select(prompt, choices=q_choices).ask()
        
        print(f"\n{prompt}")
        for i, (label, _) in enumerate(choices, 1):
            marker = " [default]" if value == default else ""
            print(f"  {i}. {label}{marker}")
        try:
            idx = int(input("Choix: ")) - 1
            return choices[idx][1] if 0 <= idx < len(choices) else default
        except:
            return default
            
    def confirm(self, prompt: str, default: bool = False) -> bool:
        if QUESTIONARY_AVAILABLE:
            return questionary.confirm(prompt, default=default).ask()
        return input(f"{prompt} (y/n): ").lower().startswith('y')
        
    def main_menu(self):
        self.clear()
        self.print_banner()
        
        print("\n=== MENU PRINCIPAL ===\n")
        
        choices = [
            ("🚀 Nouveau scan", "scan"),
            ("⚙️  Configuration", "config"),
            ("📁 Wordlists", "wordlists"),
            ("📊 Rapports", "reports"),
            ("💾 Sauvegarder config", "save"),
            ("❌ Quitter", "exit")
        ]
        
        if not RICH_AVAILABLE:
            for i, (label, _) in enumerate(choices, 1):
                print(f"{i}. {label}")
            try:
                choice = int(input("\nChoix: "))
                return choices[choice-1][1] if 1 <= choice <= len(choices) else "exit"
            except:
                return "exit"
        else:
            return self.input_select("Que faire?", choices, "scan")
            
    def config_menu(self):
        self.clear()
        self.print_banner()
        print("\n=== CONFIGURATION ===\n")
        
        self.config.target = self.input_text("🎯 URL cible", self.config.target)
        
        speed = self.input_select("⚡ Vitesse", [
            ("Lente (10 workers)", 10),
            ("Normal (30 workers)", 30),
            ("Rapide (50 workers)", 50),
            ("Aggressive (100 workers)", 100)
        ], self.config.max_workers)
        self.config.max_workers = speed
        
        depth = self.input_select("🔍 Profondeur", [
            ("Surface (1)", 1),
            ("Standard (2)", 2),
            ("Profond (3)", 3)
        ], self.config.max_depth)
        self.config.max_depth = depth
        
        if PLAYWRIGHT_AVAILABLE:
            self.config.use_js = self.confirm("🎭 Activer JS rendering?", self.config.use_js)
        else:
            print("⚠️  Playwright non disponible - JS rendering désactivé")
            self.config.use_js = False
            
        self.config.save()
        print("\n✅ Configuration sauvegardée!")
        input("\nAppuyez sur Entrée...")
        
    def wordlist_menu(self):
        self.clear()
        self.print_banner()
        print("\n=== WORDLISTS ===\n")
        
        print(f"Entrées personnalisées: {len(self.config.wordlist_custom)}")
        
        if self.confirm("Ajouter des entrées?"):
            entries = input("Chemins séparés par virgule: ").split(',')
            self.config.wordlist_custom.extend([e.strip() for e in entries])
            self.config.save()
            
        input("\nAppuyez sur Entrée...")
        
    def reports_menu(self):
        self.clear()
        self.print_banner()
        print("\n=== RAPPORTS ===\n")
        
        reports = list(Path('.').glob('crawl_report*.json'))
        if not reports:
            print("Aucun rapport trouvé")
        else:
            for i, r in enumerate(reports, 1):
                print(f"{i}. {r.name}")
            choice = input("\nOuvrir (numéro): ")
            if choice.isdigit() and 1 <= int(choice) <= len(reports):
                import webbrowser
                html = str(reports[int(choice)-1]).replace('.json', '.html')
                if os.path.exists(html):
                    webbrowser.open(f"file://{os.path.abspath(html)}")
                    
        input("\nAppuyez sur Entrée...")
        
    async def run_scan(self):
        if not self.config.target:
            print("❌ Aucune cible définie!")
            return
            
        print(f"\n🚀 Lancement du scan sur {self.config.target}")
        print(f"   Workers: {self.config.max_workers}")
        print(f"   Profondeur: {self.config.max_depth}")
        print(f"   JS Rendering: {'Oui' if self.config.use_js else 'Non'}")
        print(f"   Playwright: {'Disponible' if PLAYWRIGHT_AVAILABLE else 'Non disponible'}")
        print("\n" + "="*50)
        
        crawler = AdvancedCrawler(
            target=self.config.target,
            max_workers=self.config.max_workers,
            delay=(self.config.delay_min, self.config.delay_max),
            use_js=self.config.use_js,
            depth=self.config.max_depth
        )
        
        try:
            results = await crawler.crawl()
            crawler.generate_report()
            
            hits = len([r for r in results if r.is_interesting])
            print(f"\n✅ Scan terminé!")
            print(f"   URLs testées: {len(crawler.visited)}")
            print(f"   Findings: {hits}")
            
        except KeyboardInterrupt:
            print("\n⚠️  Interrompu par l'utilisateur")
            
        input("\nAppuyez sur Entrée...")
        
    async def run(self):
        while True:
            choice = self.main_menu()
            
            if choice == "exit":
                print("\n👋 Au revoir!")
                break
            elif choice == "scan":
                await self.run_scan()
            elif choice == "config":
                self.config_menu()
            elif choice == "wordlists":
                self.wordlist_menu()
            elif choice == "reports":
                self.reports_menu()
            elif choice == "save":
                self.config.save()
                print("✅ Sauvegardé!")

async def main():
    import argparse
    parser = argparse.ArgumentParser(description='Sensitive File Crawler')
    parser.add_argument('--interactive', '-i', action='store_true')
    parser.add_argument('target', nargs='?')
    parser.add_argument('-w', '--workers', type=int, default=30)
    parser.add_argument('--depth', type=int, default=2)
    parser.add_argument('--no-js', action='store_true')
    
    args = parser.parse_args()
    
    if args.interactive or not args.target:
        menu = InteractiveMenu()
        await menu.run()
    else:
        crawler = AdvancedCrawler(
            target=args.target,
            max_workers=args.workers,
            depth=args.depth,
            use_js=not args.no_js
        )
        results = await crawler.crawl()
        crawler.generate_report()

if __name__ == "__main__":
    asyncio.run(main())
