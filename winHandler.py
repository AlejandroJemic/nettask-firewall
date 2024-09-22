import ctypes
import pystray
from PIL import Image, ImageDraw
import sys
from utils import stop_event

def create_image():
    # Crear una imagen simple para el ícono de la bandeja
    image = Image.new('RGB', (64, 64), color=(0, 0, 100))
    dc = ImageDraw.Draw(image)
    dc.rectangle(
        (16, 16, 48, 48),
        fill=(255, 255, 255),
    )
    return image

def hide_console():
    # Ocultar la ventana de la consola
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)

def show_console():
    # Mostrar la ventana de la consola
    ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 5)

def on_show(icon, item):
    show_console()

def on_hide(icon, item):
    hide_console()
    
def on_quit(icon, item):
    stop_event.set()  # Señalar a los hilos que deben detenerse
    icon.stop()

def setup(icon):
    # Configurar el ícono y el menú de la bandeja del sistema
    icon.visible = True

def create_Tray_menu():
    hide_console()
    icon = pystray.Icon('test', create_image(), 'NetTask')
    icon.menu = pystray.Menu(
        pystray.MenuItem('Mostrar', on_show),
        pystray.MenuItem('Ocultar', on_hide),
        pystray.MenuItem('Salir', on_quit)
    )
    icon.run(setup)
