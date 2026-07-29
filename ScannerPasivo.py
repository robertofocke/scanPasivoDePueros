import time
import os
import re
import sys
from ipaddress import ip_network
from bs4 import BeautifulSoup
# Corregido: Se importó 'quote' desde 'urllib.parse' ya que se usa en 'consultar_leaks'
from urllib.parse import quote
import random
import requests

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0",
]


DIR_IMAGENES = "imagenes_shodan"



def get_random_user_agent():
    return random.choice(USER_AGENTS)   
def ips_del_rango(cidr: str, incluir_red_broadcast: bool = False) -> list[str]:
    red = ip_network(cidr, strict=False)

    if incluir_red_broadcast:
        return [str(ip) for ip in red]
    else:
        return [str(ip) for ip in red.hosts()]


def consulta_a_shodan(ip: str):
    headers = {"User-Agent": get_random_user_agent()}
    url = f"https://www.shodan.io/host/{ip}"
    try:
        response = requests.get(url, headers=headers)
        time.sleep(3)
        return response
    except requests.RequestException as e:
        print(f"Error consultando {ip}: {e}", file=sys.stderr)
        return None


def extraer_puertos_de_html(html: str) -> list[str]:
    """
    Extrae los valores del atributo href de las etiquetas <a>
    dentro de <div id="ports"> a partir de un string de HTML.
    """
    soup = BeautifulSoup(html, "html.parser")
    div_ports = soup.find("div", id="ports")
    if div_ports is None:
        return []
    puertos = []
    for a in div_ports.find_all("a", href=True):
        valor = a["href"].lstrip("#")
        puertos.append(valor)
    return puertos

def buscar_urls_shodan(html: str) -> list[str]:
    """
    Busca URLs de imágenes de Shodan dentro del HTML.
    """
    patron = r'href="(https://www\.shodan\.io/host/\d{1,3}(?:\.\d{1,3}){3}/image(?:\?p=\d+)?)"'
    return re.findall(patron, html)

def descargar_imagen(url: str, carpeta: str) -> None:
    """
    Descarga el contenido de una URL y lo guarda en disco.
    """
    try:
        time.sleep(3)
        headers = {"User-Agent": get_random_user_agent()}
        response = requests.get(url, headers=headers)
        os.makedirs(carpeta, exist_ok=True)
        # Genera un nombre de archivo a partir de la URL
        nombre = re.sub(r"[^a-zA-Z0-9]+", "_", url).strip("_") + ".png"
        ruta = os.path.join(carpeta, nombre)
        with open(ruta, "wb") as f:
            f.write(response.content)
        print(f"  Descargada: {url} -> {ruta}")
    except requests.RequestException as e:
        print(f"  Error descargando {url}: {e}", file=sys.stderr)

# Corregido: Se declaró la firma de la función aceptando el parámetro enviado desde main
    
if __name__ == "__main__":
    
    ips = ips_del_rango(str(sys.argv[1]))
    for ip in ips:
        response = consulta_a_shodan(ip)
        if response is None:
            continue
        if response.status_code != 200:
            continue
        puertos = extraer_puertos_de_html(response.text)
        imagenes = buscar_urls_shodan(response.text)
        if puertos:
            print(f"{ip}: {', '.join(puertos)}")
        else:
            pass 
        # Descarga el contenido de cada URL encontrada en "imagenes"
        for url_img in imagenes:
            descargar_imagen(url_img, DIR_IMAGENES)
