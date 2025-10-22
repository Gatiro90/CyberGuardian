from scanner import analyze_site
from colorama import Fore, Style, init

# Initialisation de colorama (Windows)
init(autoreset=True)

print(f"{Fore.CYAN}=== CyberGuardian 🛡️ ==={Style.RESET_ALL}")
url = input("Entre l'URL du site à scanner : ")

result = analyze_site(url)

if "error" in result:
    print(f"{Fore.RED}Erreur : {result['error']}{Style.RESET_ALL}")
else:
    print(f"\n{Fore.CYAN}Résultats du scan :{Style.RESET_ALL}")
    print(f"Site : {Fore.YELLOW}{result['url']}{Style.RESET_ALL}")
    print(f"Statut HTTP : {result['status_code']}")
    print(f"Connexion sécurisée : {'✅ HTTPS' if result['secure'] else '❌ Non sécurisé'}")

    print(f"\n{Fore.MAGENTA}[🧩 Analyse des en-têtes de sécurité]{Style.RESET_ALL}")

    for header, info in result["security_headers"].items():
        if info["present"]:
            print(f"{Fore.GREEN}✅ {header}{Style.RESET_ALL} → {info['description']}")
        else:
            print(f"{Fore.RED}❌ {header}{Style.RESET_ALL} → {info['description']} (manquant)")

    print(f"\nScore global : {Fore.CYAN}{result['score_percent']}%{Style.RESET_ALL}")
