
# Kelpie-Ghost: Herramienta de Pentesting con Interfaces Virtuales

## 📝 Descripción

**Kelpie-Ghost** es un script de Python 3 diseñado para pruebas de penetración y análisis de red. Su funcionalidad principal es crear interfaces de red virtuales efímeras (pares `veth`) con identidades de red (MAC e IP) aleatorias. Esto permite enviar pings y realizar escaneos desde múltiples "identidades" de red, lo que puede ser útil para evadir detecciones básicas o para simular un comportamiento de red más complejo.

La herramienta ofrece dos modos principales de operación:

1.  **Modo Clásico**: Crea múltiples interfaces virtuales simultáneamente y las usa para escanear objetivos.
2.  **Modo de Ciclos**: Crea una interfaz virtual diferente en cada ciclo de ejecución, la usa para el escaneo y luego la elimina. Este modo es ideal para pruebas de consistencia o para simular identidades cambiantes en la red.

---

## 🚀 Requisitos e Instalación

### Requisitos Previos

* **Python 3.x**
* **Privilegios de root**: El script debe ejecutarse con `sudo` para poder crear y configurar las interfaces de red.

### Instalación

1.  Clona este repositorio en tu máquina:
    ```bash
    git clone [https://github.com/tu-usuario/Kelpie-Ghost.git](https://github.com/tu-usuario/Kelpie-Ghost.git)
    cd Kelpie-Ghost
    ```

2.  Instala las dependencias de Python usando `pip`:
    ```bash
    pip3 install -r requirements.txt
    ```

### `requirements.txt`

El archivo de requisitos se encuentra en el repositorio y contiene las bibliotecas necesarias.

````

scapy

````

---

## 💻 Uso

Ejecuta el script con `sudo`. Por defecto abre un menú interactivo para elegir idioma (Español/English), modo, interfaz de red e IP/dominio objetivo.

### Modo Clásico (Múltiples Interfaces Simultáneas)

Este modo es ideal para escanear varios objetivos desde diferentes interfaces al mismo tiempo.

#### Uso Básico

Abre el menú y configura el escaneo paso a paso.
```bash
sudo python3 kelpie-ghost.py
````

#### Opciones de Línea de Comandos

  * `-t`, `--targets`: Especifica uno o más objetivos de escaneo (direcciones IP o dominios).
  * `-i`, `--interfaces`: El número de interfaces virtuales a crear. El valor por defecto es `2`.
  * `-c`, `--count`: El número de pings a enviar a cada objetivo. El valor por defecto es `3`.
  * `--mode`: Ejecuta sin menú (`classic` o `cycles`).
  * `--host-interface`: Interfaz de red principal del host (requerida cuando se usa `--mode`).
  * `--lang`: Idioma de salida (`es` o `en`). Si no se especifica, se pide al iniciar.

**Ejemplo:** Escanear `google.com` y `wikipedia.org` con 5 interfaces, enviando 5 pings a cada uno.

```bash
sudo python3 kelpie-ghost.py --mode classic --host-interface wlan0 -t 8.8.8.8 -i 5 -c 5
```

**Ejemplo en inglés:**

```bash
sudo python3 kelpie-ghost.py --lang en --mode classic --host-interface wlan0 -t google.com -i 3 -c 3
```

-----

### Modo de Ciclos (Una Interfaz por Ciclo)

Este modo crea una interfaz nueva en cada ciclo de ejecución, la usa y luego la elimina. Es útil para analizar la conectividad a lo largo del tiempo.

#### Uso Básico

Ejecuta 3 ciclos, cada uno con una interfaz diferente, escaneando `8.8.8.8`.

```bash
sudo python3 kelpie-ghost.py --mode cycles --host-interface wlan0 -t 8.8.8.8 --cycles 3
```

#### Modo Interactivo

También puedes forzar el menú interactivo con la bandera `--interactive`.

```bash
sudo python3 kelpie-ghost.py --interactive
```

-----

## 📈 Análisis de Resultados

Al finalizar la ejecución, la herramienta proporciona un resumen detallado de los resultados.

  * **En el Modo Clásico**: El resumen muestra la tasa de éxito de los pings y el tiempo de respuesta promedio (RTT) para cada objetivo, desglosado por la interfaz virtual utilizada.
  * **En el Modo de Ciclos**: Se presenta un resumen final que incluye estadísticas generales, un análisis de la consistencia de la conectividad y un desglose por objetivo. Esto te permite identificar patrones interesantes, como objetivos que son intermitentemente inaccesibles.

-----

## ⚠️ Advertencia

Esta herramienta está diseñada para fines de investigación y educativos. Su uso para actividades maliciosas o sin la debida autorización es ilegal. Por favor, utilízala de manera responsable y ética.

-----

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Si tienes ideas para mejorar la herramienta, no dudes en abrir un *issue* o enviar un *pull request*.

```
```
