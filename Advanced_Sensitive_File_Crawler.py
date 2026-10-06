#!/usr/bin/env python3
"""
Advanced Sensitive File Crawler v2.0
Features: Async crawling, JS rendering, Tech fingerprinting, Recursive discovery
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
import subprocess
from urllib.parse import urljoin, urlparse, quote, unquote
from dataclasses import dataclass, field, asdict
from typing import Set, List, Dict, Optional, Tuple, Any
from pathlib import Path
from collections import defaultdict
import logging
from datetime import datetime

# Playwright pour JS rendering
from playwright.async_api import async_playwright, Page, Browser

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('crawler.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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
    """Détection de technos pour mutation de wordlists"""
    
    SIGNATURES = {
        'wordpress': {
            'headers': ['X-Powered-By: PHP', 'wp-content'],
            'body': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'files': ['wp-config.php', 'wp-login.php', 'xmlrpc.php', 'wp-admin/']
        },
        'laravel': {
            'headers': ['X-Frame-Options: SAMEORIGIN'],
            'body': ['csrf-token', 'laravel_session', 'Mixins'],
            'files': ['.env', 'vendor/autoload.php', 'artisan', 'storage/logs/']
        },
        'django': {
            'headers': ['csrftoken', 'django'],
            'body': ['csrfmiddlewaretoken', '__debug__', 'admin/django'],
            'files': ['settings.py', 'manage.py', 'db.sqlite3', '.env']
        },
        'rails': {
            'headers': ['_session_id', 'X-Runtime'],
            'body': ['csrf-param', 'authenticity_token', 'rails'],
            'files': ['config/database.yml', 'config/secrets.yml', 'Gemfile', '.env']
        },
        'spring': {
            'headers': ['X-Application-Context'],
            'body': ['Whitelabel Error Page', 'spring-boot'],
            'files': ['application.properties', 'application.yml', 'actuator/']
        },
        'apache': {
            'headers': ['Server: Apache'],
            'body': [],
            'files': ['.htaccess', '.htpasswd', 'server-status']
        },
        'nginx': {
            'headers': ['Server: nginx'],
            'body': [],
            'files': ['nginx.conf', '.htaccess.bak']
        },
        'php': {
            'headers': ['X-Powered-By: PHP'],
            'body': ['<?php', 'phpinfo()'],
            'files': ['phpinfo.php', 'info.php', '.env.local.php']
        },
        'nodejs': {
            'headers': ['X-Powered-By: Express'],
            'body': ['node_modules', 'package.json'],
            'files': ['package.json', 'server.js', 'app.js', '.env']
        },
        'react': {
            'headers': [],
            'body': ['__REACT__', 'reactroot', 'webpack'],
            'files': ['static/js/', 'build/', '.env.production']
        },
        'angular': {
            'headers': [],
            'body': ['ng-app', 'angular', 'ng-controller'],
            'files': ['angular.json', 'src/environments/']
        }
    }

    @classmethod
    def detect(cls, headers: Dict, body: str) -> List[str]:
        detected = []
        headers_str = ' '.join([f"{k}: {v}" for k, v in headers.items()])
        
        for tech, sigs in cls.SIGNATURES.items():
            score = 0
            
            # Check headers
            for header_sig in sigs['headers']:
                if header_sig.lower() in headers_str.lower():
                    score += 2
                    
            # Check body
            for body_sig in sigs['body']:
                if body_sig in body:
                    score += 3
                    
            if score >= 3:
                detected.append(tech)
                
        return detected

class WordlistMutator:
    """Mutateur dynamique basé sur les technos détectées"""
    
    TECH_WORDLISTS = {
        'wordpress': [
            'wp-content/debug.log', 'wp-content/uploads/', 'wp-content/backup/',
            'wp-admin/install.php', 'wp-admin/setup-config.php',
            'wp-content/plugins/akismet/readme.txt',
            'wp-content/themes/twentytwenty/style.css',
            '.maintenance', 'wp-config.php.bak', 'wp-config.php~'
        ],
        'laravel': [
            'storage/logs/laravel.log', 'storage/app/public/',
            'bootstrap/cache/config.php', 'routes/web.php',
            'resources/views/', 'database/migrations/',
            '.env.testing', '.env.staging', 'artisan.backup'
        ],
        'django': [
            'static/admin/', 'media/', 'staticfiles/',
            'admin/static/', 'admin/login/',
            'settings/local.py', 'settings/production.py',
            'db.sqlite3.bak', 'fixtures/', 'migrations/'
        ],
        'rails': [
            'log/development.log', 'log/production.log',
            'tmp/cache/', 'public/assets/',
            'config/master.key', 'config/credentials.yml.enc',
            'db/development.sqlite3', 'db/schema.rb'
        ],
        'spring': [
            'actuator/env', 'actuator/configprops', 'actuator/beans',
            'actuator/threaddump', 'actuator/heapdump',
            'application-dev.properties', 'application-prod.yml',
            'target/classes/', 'src/main/resources/'
        ],
        'nodejs': [
            'node_modules/.package-lock.json', 'npm-debug.log',
            'yarn-error.log', 'package-lock.json.bak',
            '.env.development', '.env.local', 'server.log',
            'logs/', 'uploads/', 'dist/', 'build/'
        ],
        'react': [
            'static/js/main.', 'static/css/main.',
            'asset-manifest.json', 'service-worker.js',
            'precache-manifest.', 'build/static/',
            'src/config/', '.env.production.local'
        ],
        'php': [
            'composer.json', 'composer.lock',
            'vendor/autoload.php', 'var/log/',
            'php_errors.log', 'error_log',
            '.user.ini', 'php.ini', '.htaccess.txt'
        ]
    }

    def __init__(self, base_wordlist: List[str]):
        self.base = base_wordlist
        self.discovered_paths: Set[str] = set()
        
    def mutate(self, detected_techs: List[str], discovered_dirs: List[str]) -> List[str]:
        """Génère wordlist personnalisée"""
        mutated = list(self.base)
        
        # Ajoute wordlists tech-spécifiques
        for tech in detected_techs:
            if tech in self.TECH_WORDLISTS:
                mutated.extend(self.TECH_WORDLISTS[tech])
                
        # Génère variations des chemins découverts
        for directory in discovered_dirs:
            clean_dir = directory.rstrip('/')
            base_name = clean_dir.split('/')[-1] if '/' in clean_dir else clean_dir
            
            # Variantes backup
            mutated.extend([
                f"{clean_dir}.bak", f"{clean_dir}.old", f"{clean_dir}.zip",
                f"{clean_dir}.tar.gz", f"{clean_dir}/backup/",
                f"{clean_dir}/old/", f"{clean_dir}/test/"
            ])
            
            # Fichiers communs dans ce répertoire
            mutated.extend([
                f"{clean_dir}/config.php", f"{clean_dir}/index.php.bak",
                f"{clean_dir}/.htaccess", f"{clean_dir}/web.config"
            ])
            
        # Déduplication
        return list(set(mutated))

class JSRenderer:
    """Rendering JavaScript avec Playwright"""
    
    def __init__(self):
        self.browser: Optional[Browser] = None
        self.page: Optional[Page] = None
        
    async def init(self):
        playwright = await async_playwright().start()
        self.browser = await playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        
    async def render(self, url: str) -> Tuple[str, List[str], Dict]:
        """Rend une page et extrait les URLs"""
        if not self.browser:
            await self.init()
            
        self.page = await self.browser.new_page()
        
        try:
            response = await self.page.goto(url, wait_until='networkidle', timeout=30000)
            headers = await response.all_headers()
            
            # Attendre le chargement complet
            await asyncio.sleep(2)
            
            # Extraction contenu
            content = await self.page.content()
            
            # Extraction URLs depuis JS/DOM
            urls = await self.page.evaluate('''() => {
                const urls = [];
                // URLs dans les scripts
                document.querySelectorAll('script').forEach(s => {
                    if (s.src) urls.push(s.src);
                    if (s.textContent) {
                        const matches = s.textContent.match(/["\\'](\\/[^"\\']+)["\\']/g);
                        if (matches) urls.push(...matches.map(m => m.replace(/["\\']/g, '')));
                    }
                });
                // URLs dans les liens
                document.querySelectorAll('a[href]').forEach(a => urls.push(a.href));
                // URLs dans les forms
                document.querySelectorAll('form[action]').forEach(f => urls.push(f.action));
                // URLs dans fetch/API calls
                const fetchMatches = content.match(/fetch\\(["\\']([^"\\']+)["\\']/g);
                if (fetchMatches) urls.push(...fetchMatches);
                
                return [...new Set(urls)];
            }''')
            
            await self.page.close()
            return content, urls, headers
            
        except Exception as e:
            logger.error(f"JS render error for {url}: {e}")
            if self.page:
                await self.page.close()
            return "", [], {}

    async def close(self):
        if self.browser:
            await self.browser.close()

class AdvancedCrawler:
    def __init__(self, target: str, max_workers: int = 30, 
                 delay: Tuple[float, float] = (1.0, 3.0),
                 use_js: bool = True, depth: int = 2):
        self.target = target.rstrip('/')
        self.domain = urlparse(target).netloc
        self.max_workers = max_workers
        self.delay = delay
        self.use_js = use_js
        self.max_depth = depth
        
        # État
        self.visited: Set[str] = set()
        self.results: List[CrawlResult] = []
        self.error_fingerprints: Dict[int, str] = {}
        self.discovered_dirs: Set[str] = set()
        self.detected_techs: Set[str] = set()
        self.js_renderer: Optional[JSRenderer] = None
        
        # Composants
        self.mutator = WordlistMutator(self._build_base_wordlist())
        
        # Patterns
        self.sensitive_patterns = {
            'api_key': r'\b(?:api[_-]?key|apikey)["\s]*[:=]["\s]*["\'][a-zA-Z0-9]{32,64}["\']',
            'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            'private_key': r'-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'db_connection': r'(mongodb|mysql|postgres|redis|sqlserver)://[^"\s<>]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'secret': r'\b(?:secret|password|passwd|pwd)["\s]*[:=]["\s]*["\'][^"\']+["\']',
            'token': r'\b(?:token|access_token|auth_token)["\s]*[:=]["\s]*["\'][a-zA-Z0-9_-]+["\']',
            'webhook': r'https?://(?:hooks\.slack|discord\.com/api/webhooks|webhook)[^\s"<>]+',
            'ipfs': r'Qm[1-9A-HJ-NP-Za-km-z]{44}',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'ethereum': r'\b0x[a-fA-F0-9]{40}\b'
        }
        
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0'
        ]

    def _build_base_wordlist(self) -> List[str]:
        """Wordlist de base"""
        common = [
            # Environnement
            '.env', '.env.local', '.env.production', '.env.development',
            '.env.backup', '.env.save', '.env~', '.env.bak',
            'config.env', 'environment.yml', 'environment.yaml',
            
            # Backup génériques
            'backup.zip', 'backup.tar.gz', 'backup.rar', 'backup.7z',
            'www.zip', 'www.tar.gz', 'www.rar', 'site.zip', 'site.tar.gz',
            'archive.zip', 'old.zip', 'backup_old.zip',
            'dump.sql', 'database.sql', 'db.sql', 'backup.sql',
            'data.sql', 'export.sql', 'mysql.sql', 'postgres.sql',
            
            # Version control
            '.git/config', '.git/HEAD', '.git/index', '.git/logs/HEAD',
            '.git/refs/heads/master', '.git/refs/heads/main',
            '.git/description', '.git/hooks/', '.git/info/',
            '.svn/entries', '.svn/wc.db', '.svn/all-wcprops',
            '.hg/store/data', '.hg/requires', '.hg/branch',
            '.bzr/README', '.bzr/branch-format',
            '.DS_Store', 'Thumbs.db', 'desktop.ini',
            
            # IDE/Editor
            '.idea/workspace.xml', '.idea/dataSources.xml', '.idea/dataSources/',
            '.idea/sqlDataSources.xml', '.idea/dynamic.xml',
            '.vscode/settings.json', '.vscode/sftp.json', '.vscode/launch.json',
            '.vscode/tasks.json', '.vscode/extensions.json',
            'nbproject/project.xml', 'nbproject/private/',
            '.project', '.classpath', '.settings/',
            'composer.lock', 'package-lock.json', 'yarn.lock',
            
            # Logs
            'error.log', 'access.log', 'debug.log', 'application.log',
            'server.log', 'app.log', 'logs/', 'log/', 'tmp/log/',
            'log.txt', 'logs.txt', 'error_log', 'php_errors.log',
            'npm-debug.log', 'yarn-error.log',
            
            # Configs
            'config.php', 'config.json', 'config.yaml', 'config.yml', 'config.xml',
            'configuration.php', 'settings.php', 'settings.json',
            'database.yml', 'database.yaml', 'database.json',
            'app.config', 'web.config', 'application.config',
            'phpinfo.php', 'info.php', 'test.php', 'php.php',
            
            # API/Docs
            'api-docs', 'swagger.json', 'swagger.yaml', 'openapi.json',
            'openapi.yaml', 'api/v1/', 'api/v2/', 'graphql',
            'postman.json', 'insomnia.json',
            
            # Framework paths
            'phpmyadmin/', 'pma/', 'adminer.php', 'myadmin/',
            'wp-admin/', 'wp-content/', 'wp-includes/',
            'administrator/', 'admin/', 'backend/', 'manage/',
            'api/', 'rest/', 'graphql/', 'graphiql/',
            'actuator/', 'health', 'metrics', 'prometheus',
            
            # Déploiement
            'deploy/', 'deployment/', 'deploy.php', 'deploy.sh',
            'docker-compose.yml', 'Dockerfile', '.docker/',
            'kubernetes/', 'k8s/', 'helm/', 'chart/',
            'terraform/', 'terraform.tfstate', '.terraform/',
            'ansible/', 'puppet/', 'chef/',
            
            # Tests
            'test/', 'tests/', 'testing/', 'phpunit.xml',
            'test.php', 'test.html', 'test/', '_test/',
            'spec/', 'specs/', 'cypress/', 'cypress.json',
            
            # Divers sensibles
            'robots.txt', 'sitemap.xml', 'crossdomain.xml',
            'clientaccesspolicy.xml', 'security.txt',
            '.well-known/security.txt', '.well-known/openid-configuration',
            'key.pem', 'cert.pem', 'private.key', 'server.key',
            'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
            'authorized_keys', 'known_hosts', '.ssh/',
            '.htaccess', '.htpasswd', 'nginx.conf', 'apache.conf',
            'webalizer/', 'awstats/', 'stats/', 'analytics/'
        ]
        
        # Variantes encodées
        encoded = []
        for word in common:
            encoded.append(quote(word, safe=''))
            encoded.append(word.replace('/', '%2f'))
            encoded.append(word.replace('/', '%252f'))  # Double encoding
            
        return list(set(common + encoded))

    async def _get_session(self) -> aiohttp.ClientSession:
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9,fr;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
            'Pragma': 'no-cache'
        }
        
        connector = aiohttp.TCPConnector(
            limit=100,
            limit_per_host=30,
            ttl_dns_cache=300,
            use_dns_cache=True,
            ssl=False
        )
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        
        return aiohttp.ClientSession(
            headers=headers,
            connector=connector,
            timeout=timeout,
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
        return entropy / 8  # Normalisé

    async def _extract_urls_from_js(self, content: str, base_url: str) -> List[str]:
        """Extraction agressive des URLs depuis JS/HTML"""
        urls = []
        
        # Patterns d'URLs
        patterns = [
            r'["\'](\/[a-zA-Z0-9_\-\/\.]+\.[a-zA-Z0-9]+)["\']',  # Chemins absolus
            r'["\']([a-zA-Z0-9_\-\/\.]+\.[a-zA-Z0-9]{2,6})["\']',  # Relatifs
            r'url\s*:\s*["\']([^"\']+)["\']',  # Propriété url
            r'href\s*=\s*["\']([^"\']+)["\']',  # Liens
            r'src\s*=\s*["\']([^"\']+)["\']',  # Sources
            r'action\s*=\s*["\']([^"\']+)["\']',  # Forms
            r'fetch\(["\']([^"\']+)["\']',  # Fetch API
            r'axios\.[get|post|put|delete]\(["\']([^"\']+)["\']',  # Axios
            r'\/api\/[a-zA-Z0-9_\-\/]+',  # Endpoints API
            r'\/v\d+\/[a-zA-Z0-9_\-\/]+',  # API versioning
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
                    
        # Extraction des répertoires
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
        
        # Détection technos
        text_content = ""
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            pass
            
        techs = TechFingerprint.detect(headers, text_content)
        self.detected_techs.update(techs)
        
        result = CrawlResult(
            url=url,
            status=status,
            size=size,
            content_hash=content_hash,
            tech_detected=techs,
            content_type=content_type,
            response_time=time.time() - start_time
        )
        
        # Skip si page d'erreur calibrée
        if status in self.error_fingerprints:
            if content_hash == self.error_fingerprints[status]:
                return result
        
        # Analyse entropie
        if text_content:
            entropy = self._calculate_entropy(text_content[:2000])
            if entropy > 0.7:
                result.findings.append(f"High entropy: {entropy:.2f}")
                result.is_interesting = True
        
        # Pattern matching
        for finding_type, pattern in self.sensitive_patterns.items():
            matches = re.findall(pattern, text_content, re.IGNORECASE)
            if matches:
                # Masquer les valeurs sensibles dans les logs
                masked = [m[:10] + '...' if len(str(m)) > 10 else m for m in matches[:3]]
                result.findings.append(f"{finding_type}: {len(matches)} matches ({masked})")
                result.is_interesting = True
        
        # Extensions sensibles
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        sensitive_exts = ['.sql', '.env', '.config', '.backup', '.dump', '.key', 
                         '.pem', '.p12', '.pfx', '.keystore', '.jks']
        if any(path_lower.endswith(ext) for ext in sensitive_exts):
            result.is_interesting = True
            result.findings.append("Sensitive extension")
            
        # Fichiers gros = potentiellement dumps
        if size > 5 * 1024 * 1024:  # 5MB
            result.is_interesting = True
            result.findings.append(f"Large file: {size / 1024 / 1024:.2f}MB")
            
        # Extraction URLs depuis contenu
        discovered = await self._extract_urls_from_js(text_content, url)
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
                        logger.info(f"[HIT] {url} | Status: {response.status} | "
                                  f"Size: {len(content)} | Tech: {result.tech_detected} | "
                                  f"Findings: {result.findings}")
                    
                    # Crawl récursif des URLs découvertes
                    if depth < self.max_depth and result.discovered_paths:
                        for new_url in result.discovered_paths:
                            if self.domain in new_url:
                                asyncio.create_task(
                                    self._fetch(session, new_url, semaphore, depth + 1)
                                )
                    
                    return result
                    
            except asyncio.TimeoutError:
                logger.debug(f"Timeout: {url}")
            except aiohttp.ClientError as e:
                logger.debug(f"Client error {url}: {e}")
            except Exception as e:
                logger.debug(f"Error {url}: {e}")
                
            return None

    async def _calibrate_errors(self, session: aiohttp.ClientSession):
        logger.info("Calibrating error pages...")
        
        random_paths = [
            ''.join(random.choices(string.ascii_lowercase + string.digits, k=25))
            for _ in range(3)
        ]
        
        for path in random_paths:
            try:
                url = f"{self.target}/{path}"
                async with session.get(url, ssl=False) as response:
                    content = await response.read()
                    self.error_fingerprints[response.status] = hashlib.md5(content).hexdigest()
            except:
                pass
                
        logger.info(f"Calibrated {len(self.error_fingerprints)} error signatures")

    async def _js_crawl(self, urls: List[str]) -> List[str]:
        """Crawl avec rendering JS pour URLs critiques"""
        if not self.use_js or not self.js_renderer:
            return []
            
        discovered = []
        critical_paths = ['/login', '/admin', '/dashboard', '/app', '/portal']
        
        for path in critical_paths:
            url = f"{self.target}{path}"
            try:
                content, urls, headers = await self.js_renderer.render(url)
                
                # Analyse du contenu rendu
                result = await self._analyze_content(url, content.encode(), 200, headers)
                if result.is_interesting:
                    self.results.append(result)
                    
                discovered.extend(urls)
                
            except Exception as e:
                logger.error(f"JS crawl error for {url}: {e}")
                
        return discovered

    async def crawl(self) -> List[CrawlResult]:
        session = await self._get_session()
        semaphore = asyncio.Semaphore(self.max_workers)
        
        if self.use_js:
            self.js_renderer = JSRenderer()
            await self.js_renderer.init()
        
        await self._calibrate_errors(session)
        
        # Phase 1: Wordlist de base
        urls_phase1 = [f"{self.target}/{word}" for word in self.mutator.base]
        
        # Phase 2: Crawl initial
        logger.info(f"Phase 1: Testing {len(urls_phase1)} URLs...")
        tasks = [self._fetch(session, url, semaphore, 0) for url in urls_phase1]
        phase1_results = await asyncio.gather(*tasks)
        
        # Phase 3: JS rendering sur chemins critiques
        if self.use_js:
            logger.info("Phase 2: JavaScript rendering...")
            await self._js_crawl([])
        
        # Phase 4: Mutation et re-crawl avec wordlist enrichie
        logger.info("Phase 3: Dynamic wordlist mutation...")
        mutated = self.mutator.mutate(
            list(self.detected_techs), 
            list(self.discovered_dirs)
        )
        
        new_urls = [f"{self.target}/{word}" for word in mutated 
                   if f"{self.target}/{word}" not in self.visited]
        
        if new_urls:
            logger.info(f"Phase 3: Testing {len(new_urls)} mutated URLs...")
            tasks = [self._fetch(session, url, semaphore, 0) for url in new_urls]
            phase3_results = await asyncio.gather(*tasks)
        else:
            phase3_results = []
        
        await session.close()
        if self.js_renderer:
            await self.js_renderer.close()
        
        self.results = [r for r in phase1_results + phase3_results if r is not None]
        return self.results

    def generate_report(self, output_file: str = "crawl_report.json"):
        hits = [r for r in self.results if r.is_interesting]
        
        report = {
            'scan_info': {
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'total_tested': len(self.visited),
                'total_responses': len(self.results),
                'interesting_findings': len(hits),
                'technologies_detected': list(self.detected_techs),
                'directories_discovered': list(self.discovered_dirs)
            },
            'findings': [
                {
                    'url': r.url,
                    'status': r.status,
                    'size': r.size,
                    'content_type': r.content_type,
                    'technologies': r.tech_detected,
                    'findings': r.findings,
                    'response_time': round(r.response_time, 3),
                    'severity': self._calculate_severity(r)
                }
                for r in hits
            ],
            'statistics': {
                'status_codes': self._status_distribution(),
                'tech_distribution': self._tech_distribution(),
                'file_types': self._file_type_distribution()
            }
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
            
        self._generate_html_report(report, output_file.replace('.json', '.html'))
        
        logger.info(f"\n{'='*60}")
        logger.info(f"SCAN COMPLETE")
        logger.info(f"{'='*60}")
        logger.info(f"Total tested: {len(self.visited)}")
        logger.info(f"Interesting findings: {len(hits)}")
        logger.info(f"Technologies: {list(self.detected_techs)}")
        logger.info(f"Reports saved: {output_file}, {output_file.replace('.json', '.html')}")
        
        return report

    def _calculate_severity(self, result: CrawlResult) -> str:
        if any(k in ' '.join(result.findings).lower() for k in ['private key', 'password', 'secret', 'aws_key']):
            return 'CRITICAL'
        elif result.status == 200 and any(result.url.endswith(ext) for ext in ['.env', '.sql', '.config']):
            return 'HIGH'
        elif result.is_interesting:
            return 'MEDIUM'
        return 'LOW'

    def _status_distribution(self) -> Dict:
        dist = defaultdict(int)
        for r in self.results:
            dist[r.status] += 1
        return dict(dist)

    def _tech_distribution(self) -> Dict:
        dist = defaultdict(int)
        for r in self.results:
            for t in r.tech_detected:
                dist[t] += 1
        return dict(dist)

    def _file_type_distribution(self) -> Dict:
        dist = defaultdict(int)
        for r in self.results:
            ext = r.url.split('.')[-1] if '.' in r.url else 'none'
            if len(ext) < 6:
                dist[ext] += 1
        return dict(dist)

    def _generate_html_report(self, data: Dict, output_file: str):
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Crawl Report - {data['scan_info']['target']}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #e0e0e0; }}
        h1, h2 {{ color: #00ff88; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #2a2a2a; padding: 20px; border-radius: 8px; border-left: 4px solid #00ff88; }}
        .finding {{ background: #2a2a2a; margin: 10px 0; padding: 15px; border-radius: 8px; border-left: 4px solid #ffaa00; }}
        .CRITICAL {{ border-left-color: #ff0044 !important; }}
        .HIGH {{ border-left-color: #ff6600 !important; }}
        .MEDIUM {{ border-left-color: #ffaa00 !important; }}
        .LOW {{ border-left-color: #00ff88 !important; }}
        .url {{ font-family: monospace; color: #66ccff; word-break: break-all; }}
        .finding-list {{ color: #ffaa88; }}
        .tech-tag {{ display: inline-block; background: #444; padding: 4px 8px; margin: 2px; border-radius: 4px; font-size: 12px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid #444; }}
        th {{ background: #333; }}
    </style>
</head>
<body>
    <h1>🔍 Sensitive File Discovery Report</h1>
    <p>Target: <strong>{data['scan_info']['target']}</strong></p>
    <p>Scan Date: {data['scan_info']['timestamp']}</p>
    
    <div class="stats">
        <div class="stat-box">
            <h3>{data['scan_info']['total_tested']}</h3>
            <p>URLs Tested</p>
        </div>
        <div class="stat-box">
            <h3>{data['scan_info']['interesting_findings']}</h3>
            <p>Findings</p>
        </div>
        <div class="stat-box">
            <h3>{len(data['scan_info']['technologies_detected'])}</h3>
            <p>Technologies</p>
        </div>
        <div class="stat-box">
            <h3>{len(data['scan_info']['directories_discovered'])}</h3>
            <p>Directories</p>
        </div>
    </div>

    <h2>🚨 Critical Findings</h2>
    {''.join([f'<div class="finding {f["severity"]}"><div class="url">{f["url"]}</div><div>Status: {f["status"]} | Size: {f["size"]} | Time: {f["response_time"]}s</div><div class="finding-list">{", ".join(f["findings"])}</div><div>Tech: {", ".join([f"<span class=\\"tech-tag\\">{t}</span>" for t in f["technologies"]])}</div></div>' for f in data['findings'] if f['severity'] in ['CRITICAL', 'HIGH']])}

    <h2>📊 Technology Detection</h2>
    <div>{''.join([f'<span class="tech-tag">{k}: {v}</span>' for k, v in data['statistics']['tech_distribution'].items()])}</div>

    <h2>📁 File Types Discovered</h2>
    <table>
        <tr><th>Extension</th><th>Count</th></tr>
        {''.join([f'<tr><td>{k}</td><td>{v}</td></tr>' for k, v in sorted(data['statistics']['file_types'].items(), key=lambda x: -x[1])[:10]])}
    </table>

    <h2>📋 All Findings</h2>
    <table>
        <tr><th>Severity</th><th>URL</th><th>Status</th><th>Findings</th></tr>
        {''.join([f'<tr class="{f["severity"]}"><td>{f["severity"]}</td><td class="url">{f["url"]}</td><td>{f["status"]}</td><td>{", ".join(f["findings"])}</td></tr>' for f in data['findings']])}
    </table>
</body>
</html>"""
        
        with open(output_file, 'w') as f:
            f.write(html)

async def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='Advanced Sensitive File Crawler',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python crawler.py https://example.com
  python crawler.py https://example.com -w 50 --no-js -d 3
  python crawler.py https://example.com --delay 2.0 5.0 -o report.json
        """
    )
    parser.add_argument('target', help='Target URL (https://example.com)')
    parser.add_argument('-w', '--workers', type=int, default=30, help='Concurrent workers')
    parser.add_argument('-d', '--delay', type=float, nargs=2, default=[1.0, 3.0], 
                       help='Delay range (min max)')
    parser.add_argument('--depth', type=int, default=2, help='Crawl depth')
    parser.add_argument('--no-js', action='store_true', help='Disable JS rendering')
    parser.add_argument('-o', '--output', default='crawl_report.json', help='Output file')
    
    args = parser.parse_args()
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║     Advanced Sensitive File Crawler v2.0                 ║
    ║     Target: {args.target:<43} ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    crawler = AdvancedCrawler(
        target=args.target,
        max_workers=args.workers,
        delay=tuple(args.delay),
        use_js=not args.no_js,
        depth=args.depth
    )
    
    try:
        results = await crawler.crawl()
        crawler.generate_report(args.output)
    except KeyboardInterrupt:
        logger.info("\nInterrupted by user")
        crawler.generate_report(args.output)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
