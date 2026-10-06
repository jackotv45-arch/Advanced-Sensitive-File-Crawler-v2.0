#!/usr/bin/env python3
"""
Advanced Sensitive File Crawler v2.1
With Interactive Menu Interface
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

# Playwright
from playwright.async_api import async_playwright, Page, Browser

# Interactive menu libraries
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.layout import Layout
    from rich.live import Live
    from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
    from rich.syntax import Syntax
    from rich.tree import Tree
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

try:
    import questionary
    from questionary import Choice, Separator
    QUESTIONARY_AVAILABLE = True
except ImportError:
    QUESTIONARY_AVAILABLE = False

# Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[logging.FileHandler('crawler.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

console = Console() if RICH_AVAILABLE else None

@dataclass
class CrawlConfig:
    """Configuration persistante"""
    target: str = ""
    max_workers: int = 30
    delay_min: float = 1.0
    delay_max: float = 3.0
    max_depth: int = 2
    use_js: bool = True
    use_tor: bool = False
    proxy: str = ""
    wordlist_custom: List[str] = field(default_factory=list)
    extensions: List[str] = field(default_factory=lambda: ['.env', '.sql', '.bak', '.zip'])
    headers_custom: Dict[str, str] = field(default_factory=dict)
    output_format: str = "json"
    save_screenshots: bool = False
    
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

class InteractiveMenu:
    """Menu interactif Rich + Questionary"""
    
    def __init__(self):
        self.config = CrawlConfig.load()
        self.banner = """
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ███████╗███████╗███╗   ██╗███████╗██╗████████╗██╗   ██╗███████╗ ║
║   ██╔════╝██╔════╝████╗  ██║██╔════╝██║╚══██╔══╝██║   ██║██╔════╝ ║
║   ███████╗█████╗  ██╔██╗ ██║███████╗██║   ██║   ██║   ██║███████╗ ║
║   ╚════██║██╔══╝  ██║╚██╗██║╚════██║██║   ██║   ██║   ██║╚════██║ ║
║   ███████║███████╗██║ ╚████║███████║██║   ██║   ╚██████╔╝███████║ ║
║   ╚══════╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝   ╚═╝    ╚═════╝ ╚══════╝ ║
║                                                                  ║
║              [bold cyan]Advanced Sensitive File Crawler v2.1[/]              ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
        """
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def print_banner(self):
        if console:
            console.print(Panel(self.banner, border_style="cyan", box=box.DOUBLE))
        else:
            print(self.banner)
            
    def print_status(self, message: str, style: str = "info"):
        if console:
            styles = {
                "info": "[blue]ℹ[/]",
                "success": "[green]✓[/]",
                "warning": "[yellow]⚠[/]",
                "error": "[red]✗[/]",
                "critical": "[red]🔥[/]"
            }
            console.print(f"{styles.get(style, 'ℹ')} {message}")
        else:
            print(f"[{style.upper()}] {message}")
            
    def main_menu(self) -> str:
        """Menu principal"""
        self.clear_screen()
        self.print_banner()
        
        if QUESTIONARY_AVAILABLE:
            choice = questionary.select(
                "Que souhaitez-vous faire ?",
                choices=[
                    Choice("🚀 Lancer un nouveau scan", "new_scan"),
                    Choice("⚙️  Configuration rapide", "quick_config"),
                    Choice("🔧 Configuration avancée", "advanced_config"),
                    Choice("📁 Gérer les wordlists", "wordlists"),
                    Choice("📊 Voir les rapports précédents", "reports"),
                    Choice("🔄 Charger une configuration", "load_config"),
                    Choice("💾 Sauvegarder la configuration", "save_config"),
                    Choice("❌ Quitter", "exit")
                ],
                qmark="",
                pointer="▶"
            ).ask()
        else:
            self.print_status("Menu Principal:", "info")
            print("\n1. 🚀 Lancer un nouveau scan")
            print("2. ⚙️  Configuration rapide")
            print("3. 🔧 Configuration avancée")
            print("4. 📁 Gérer les wordlists")
            print("5. 📊 Voir les rapports précédents")
            print("6. 🔄 Charger une configuration")
            print("7. 💾 Sauvegarder la configuration")
            print("8. ❌ Quitter")
            
            choice_map = {
                "1": "new_scan",
                "2": "quick_config", 
                "3": "advanced_config",
                "4": "wordlists",
                "5": "reports",
                "6": "load_config",
                "7": "save_config",
                "8": "exit"
            }
            choice = choice_map.get(input("\nChoix: "), "exit")
            
        return choice or "exit"
        
    def quick_config_menu(self):
        """Configuration rapide"""
        self.clear_screen()
        self.print_banner()
        self.print_status("Configuration Rapide", "info")
        
        if QUESTIONARY_AVAILABLE:
            self.config.target = questionary.text(
                "🎯 URL cible:",
                default=self.config.target,
                validate=lambda x: x.startswith(('http://', 'https://')) or "URL doit commencer par http:// ou https://"
            ).ask()
            
            self.config.max_workers = questionary.select(
                "⚡ Vitesse du scan:",
                choices=[
                    Choice("🐌 Lent (10 workers, stealth)", 10),
                    Choice("🚶 Normal (30 workers)", 30),
                    Choice("🏃 Rapide (50 workers)", 50),
                    Choice("🚀 Aggressif (100 workers)", 100)
                ],
                default=self.config.max_workers
            ).ask()
            
            depth_choice = questionary.select(
                "🔍 Profondeur d'analyse:",
                choices=[
                    Choice("Surface (1 niveau)", 1),
                    Choice("Standard (2 niveaux)", 2),
                    Choice("Profond (3 niveaux)", 3),
                    Choice("Complet (5 niveaux)", 5)
                ],
                default=self.config.max_depth
            ).ask()
            self.config.max_depth = depth_choice
            
            self.config.use_js = questionary.confirm(
                "🎭 Activer le rendu JavaScript (plus lent mais plus complet)?",
                default=self.config.use_js
            ).ask()
            
        else:
            self.config.target = input(f"🎯 URL cible [{self.config.target}]: ") or self.config.target
            self.config.max_workers = int(input(f"⚡ Workers [{self.config.max_workers}]: ") or self.config.max_workers)
            self.config.max_depth = int(input(f"🔍 Profondeur [{self.config.max_depth}]: ") or self.config.max_depth)
            self.config.use_js = input(f"🎭 JavaScript (y/n) [{'y' if self.config.use_js else 'n'}]: ").lower() != 'n'
            
        self.config.save()
        self.print_status("Configuration sauvegardée!", "success")
        input("\nAppuyez sur Entrée pour continuer...")
        
    def advanced_config_menu(self):
        """Configuration avancée avec tableaux Rich"""
        while True:
            self.clear_screen()
            self.print_banner()
            
            if console:
                # Affichage tableau de configuration
                table = Table(title="Configuration Actuelle", box=box.ROUNDED)
                table.add_column("Paramètre", style="cyan")
                table.add_column("Valeur", style="green")
                
                table.add_row("🎯 Target", self.config.target or "Non défini")
                table.add_row("⚡ Workers", str(self.config.max_workers))
                table.add_row("⏱️  Delay", f"{self.config.delay_min}s - {self.config.delay_max}s")
                table.add_row("🔍 Depth", str(self.config.max_depth))
                table.add_row("🎭 JavaScript", "✓" if self.config.use_js else "✗")
                table.add_row("🧅 Tor", "✓" if self.config.use_tor else "✗")
                table.add_row("🌐 Proxy", self.config.proxy or "Aucun")
                table.add_row("📄 Output", self.config.output_format)
                
                console.print(table)
            else:
                print(f"\nConfiguration:")
                for k, v in asdict(self.config).items():
                    print(f"  {k}: {v}")
                    
            if QUESTIONARY_AVAILABLE:
                choice = questionary.select(
                    "Modifier:",
                    choices=[
                        Choice("🎯 URL Cible", "target"),
                        Choice("⚡ Workers", "workers"),
                        Choice("⏱️  Délai entre requêtes", "delay"),
                        Choice("🔍 Profondeur", "depth"),
                        Choice("🎭 JavaScript rendering", "js"),
                        Choice("🧅 Mode Tor", "tor"),
                        Choice("🌐 Proxy personnalisé", "proxy"),
                        Choice("📄 Format de sortie", "output"),
                        Choice("🔙 Retour", "back")
                    ]
                ).ask()
            else:
                print("\n1. URL Cible")
                print("2. Workers")
                print("3. Délai")
                print("4. Profondeur")
                print("5. JavaScript")
                print("6. Tor")
                print("7. Proxy")
                print("8. Format sortie")
                print("9. Retour")
                choice = input("Choix: ")
                choice_map = {str(i): c for i, c in enumerate(
                    ["target", "workers", "delay", "depth", "js", "tor", "proxy", "output", "back"], 1
                )}
                choice = choice_map.get(choice, "back")
                
            if choice == "back":
                break
            elif choice == "target":
                self.config.target = input("URL: ")
            elif choice == "workers":
                self.config.max_workers = int(input("Workers (10-200): ") or 30)
            elif choice == "delay":
                self.config.delay_min = float(input("Délai min (s): ") or 1.0)
                self.config.delay_max = float(input("Délai max (s): ") or 3.0)
            elif choice == "depth":
                self.config.max_depth = int(input("Profondeur (1-5): ") or 2)
            elif choice == "js":
                self.config.use_js = not self.config.use_js
            elif choice == "tor":
                self.config.use_tor = not self.config.use_tor
            elif choice == "proxy":
                self.config.proxy = input("Proxy (http://host:port): ")
            elif choice == "output":
                self.config.output_format = input("Format (json/html/both): ") or "json"
                
            self.config.save()
            
    def wordlist_menu(self):
        """Gestion des wordlists personnalisées"""
        self.clear_screen()
        self.print_banner()
        self.print_status("Gestion des Wordlists", "info")
        
        if self.config.wordlist_custom:
            print("\nWordlist personnalisée actuelle:")
            for i, word in enumerate(self.config.wordlist_custom[:20], 1):
                print(f"  {i}. {word}")
            if len(self.config.wordlist_custom) > 20:
                print(f"  ... et {len(self.config.wordlist_custom) - 20} autres")
        else:
            print("\nAucune wordlist personnalisée")
            
        print("\n1. Ajouter des entrées")
        print("2. Charger depuis un fichier")
        print("3. Vider la wordlist")
        print("4. Retour")
        
        choice = input("\nChoix: ")
        
        if choice == "1":
            entries = input("Entrées séparées par des virgules: ").split(',')
            self.config.wordlist_custom.extend([e.strip() for e in entries])
            self.print_status(f"{len(entries)} entrées ajoutées", "success")
        elif choice == "2":
            filepath = input("Chemin du fichier: ")
            try:
                with open(filepath, 'r') as f:
                    new_words = [line.strip() for line in f if line.strip()]
                self.config.wordlist_custom.extend(new_words)
                self.print_status(f"{len(new_words)} entrées chargées", "success")
            except Exception as e:
                self.print_status(f"Erreur: {e}", "error")
        elif choice == "3":
            self.config.wordlist_custom = []
            self.print_status("Wordlist vidée", "success")
            
        self.config.save()
        input("\nAppuyez sur Entrée...")
        
    def reports_menu(self):
        """Visualisation des rapports précédents"""
        self.clear_screen()
        self.print_banner()
        
        reports = list(Path('.').glob('crawl_report*.json'))
        
        if not reports:
            self.print_status("Aucun rapport trouvé", "warning")
            input("\nAppuyez sur Entrée...")
            return
            
        self.print_status(f"Rapports trouvés: {len(reports)}", "info")
        
        for i, report in enumerate(reports, 1):
            try:
                with open(report, 'r') as f:
                    data = json.load(f)
                    target = data.get('scan_info', {}).get('target', 'Unknown')
                    date = data.get('scan_info', {}).get('timestamp', 'Unknown')
                    findings = len(data.get('findings', []))
                    
                    if console:
                        console.print(f"[{i}] [cyan]{report.name}[/]")
                        console.print(f"    Target: {target}")
                        console.print(f"    Date: {date}")
                        console.print(f"    Findings: [red]{findings}[/]" if findings > 0 else f"    Findings: {findings}")
                    else:
                        print(f"{i}. {report.name} - {target} ({findings} findings)")
            except:
                pass
                
        choice = input("\nNuméro du rapport à ouvrir (ou Entrée pour retour): ")
        if choice.isdigit() and 1 <= int(choice) <= len(reports):
            report_path = reports[int(choice) - 1]
            html_path = str(report_path).replace('.json', '.html')
            
            if os.path.exists(html_path):
                import webbrowser
                webbrowser.open(f"file://{os.path.abspath(html_path)}")
                self.print_status("Ouverture du rapport HTML...", "success")
            else:
                with open(report_path, 'r') as f:
                    data = json.load(f)
                    print(json.dumps(data, indent=2))
                    
        input("\nAppuyez sur Entrée...")
        
    async def run_scan_with_progress(self):
        """Lancement du scan avec barre de progression Rich"""
        if not self.config.target:
            self.print_status("Aucune cible définie!", "error")
            return None
            
        crawler = AdvancedCrawler(
            target=self.config.target,
            max_workers=self.config.max_workers,
            delay=(self.config.delay_min, self.config.delay_max),
            use_js=self.config.use_js,
            depth=self.config.max_depth
        )
        
        if console:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=console
            ) as progress:
                task = progress.add_task("[cyan]Scanning...", total=None)
                
                # Wrapper pour mettre à jour la progression
                original_crawl = crawler.crawl
                
                async def crawl_with_update():
                    results = await original_crawl()
                    progress.update(task, completed=100)
                    return results
                    
                results = await crawl_with_update()
        else:
            results = await crawler.crawl()
            
        output_file = f"crawl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        crawler.generate_report(output_file)
        
        # Résumé final
        hits = [r for r in results if r.is_interesting]
        
        if console:
            console.print("\n")
            console.print(Panel(
                f"[green]Scan terminé![/]\n"
                f"URLs testées: {len(crawler.visited)}\n"
                f"Findings: [red]{len(hits)}[/] intéressants\n"
                f"Technologies: {', '.join(crawler.detected_techs) or 'Aucune'}\n"
                f"Rapport: {output_file}",
                title="Résumé",
                border_style="green"
            ))
        else:
            print(f"\n✓ Scan terminé!")
            print(f"  URLs testées: {len(crawler.visited)}")
            print(f"  Findings: {len(hits)}")
            
        return results
        
    async def run(self):
        """Boucle principale"""
        while True:
            choice = self.main_menu()
            
            if choice == "exit":
                self.print_status("Au revoir!", "info")
                break
            elif choice == "new_scan":
                if not self.config.target:
                    self.print_status("Définissez d'abord une cible!", "error")
                    input("Appuyez sur Entrée...")
                    continue
                await self.run_scan_with_progress()
                input("\nAppuyez sur Entrée pour continuer...")
            elif choice == "quick_config":
                self.quick_config_menu()
            elif choice == "advanced_config":
                self.advanced_config_menu()
            elif choice == "wordlists":
                self.wordlist_menu()
            elif choice == "reports":
                self.reports_menu()
            elif choice == "load_config":
                self.config = CrawlConfig.load()
                self.print_status("Configuration chargée!", "success")
                input("Appuyez sur Entrée...")
            elif choice == "save_config":
                self.config.save()
                self.print_status("Configuration sauvegardée!", "success")
                input("Appuyez sur Entrée...")

# [Le reste du code du crawler (AdvancedCrawler, TechFingerprint, etc.) 
#  reste identique à la version précédente...]

async def main():
    import argparse
    parser = argparse.ArgumentParser(description='Advanced Sensitive File Crawler')
    parser.add_argument('--interactive', '-i', action='store_true', help='Mode interactif')
    parser.add_argument('target', nargs='?', help='Target URL')
    parser.add_argument('-w', '--workers', type=int, default=30)
    parser.add_argument('-d', '--delay', type=float, nargs=2, default=[1.0, 3.0])
    parser.add_argument('--depth', type=int, default=2)
    parser.add_argument('--no-js', action='store_true')
    parser.add_argument('-o', '--output', default='crawl_report.json')
    
    args = parser.parse_args()
    
    if args.interactive or (not args.target and len(sys.argv) == 1):
        # Mode interactif
        if not RICH_AVAILABLE:
            print("Installation de rich recommandée: pip install rich")
        if not QUESTIONARY_AVAILABLE:
            print("Installation de questionary recommandée: pip install questionary")
            
        menu = InteractiveMenu()
        await menu.run()
    else:
        # Mode CLI standard
        if not args.target:
            print("Usage: python crawler.py <target> ou python crawler.py --interactive")
            sys.exit(1)
            
        crawler = AdvancedCrawler(
            target=args.target,
            max_workers=args.workers,
            delay=tuple(args.delay),
            use_js=not args.no_js,
            depth=args.depth
        )
        
        results = await crawler.crawl()
        crawler.generate_report(args.output)

if __name__ == "__main__":
    asyncio.run(main())
