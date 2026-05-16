#!/usr/bin/env python3
"""
Virtual Network Interface Pentesting Tool
Crear interfaces virtuales y enviar pings desde diferentes identidades de red
Uso: sudo python3 virtual_pentest.py
"""

import os
import sys
import time
import random
import subprocess
import socket
import signal
from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.sendrecv import sr1
import argparse
import threading
from datetime import datetime

class VirtualNetworkTool:
    def __init__(self):
        self.virtual_interfaces = []
        self.results = []
        self.host_main_interface = None
        self.cleanup_done = False
        self.language = "es"
        self.default_ping_count = 3

    def t(self, es, en):
        """Return translated text based on selected language"""
        return es if self.language == "es" else en

    def choose_language(self):
        """Allow user to choose Spanish or English"""
        print("\n🌍 Idioma / Language")
        print("   1. Español")
        print("   2. English")

        while True:
            choice = input("Selecciona idioma / Select language (1/2): ").strip()
            if choice == "1":
                self.language = "es"
                print("✅ Idioma seleccionado: Español")
                return
            if choice == "2":
                self.language = "en"
                print("✅ Selected language: English")
                return
            print("❌ Opción inválida / Invalid option")
        
    def check_privileges(self):
        """Verificar si se ejecuta como root"""
        if os.geteuid() != 0:
            print(self.t(
                "❌ Este script requiere privilegios de root (sudo)",
                "❌ This script requires root privileges (sudo)",
            ))
            sys.exit(1)
        print(self.t("✅ Privilegios verificados", "✅ Privileges verified"))
        
    def generate_random_mac(self):
        """Generar MAC address aleatoria"""
        mac = [0x02, 0x00, 0x00,
               random.randint(0x00, 0x7f),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))

    def get_available_interfaces(self):
        """Obtener interfaces de red físicas/activas del sistema"""
        try:
            up_with_ipv4 = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "up", "scope", "global"],
                capture_output=True,
                text=True,
                check=True,
            )
            preferred = []
            for line in up_with_ipv4.stdout.splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                iface = parts[1]
                if iface == "lo" or iface.startswith("veth"):
                    continue
                if iface not in preferred:
                    preferred.append(iface)

            if preferred:
                return preferred

            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                check=True,
            )
            interfaces = []
            for line in result.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue
                iface = parts[1].strip()
                if iface == "lo" or iface.startswith("veth"):
                    continue
                interfaces.append(iface)
            return interfaces
        except Exception:
            return []

    def cleanup_stale_virtual_interfaces(self):
        """Eliminar interfaces virtuales huérfanas de ejecuciones anteriores"""
        try:
            result = subprocess.run(
                ["ip", "-o", "link", "show"],
                capture_output=True,
                text=True,
                check=True,
            )
            removed = []
            managed_prefixes = ("vpen", "cycle", "veth_pen")

            for line in result.stdout.splitlines():
                parts = line.split(":", 2)
                if len(parts) < 2:
                    continue

                iface = parts[1].strip().split("@", 1)[0]
                if not iface.endswith("0"):
                    continue
                if not any(iface.startswith(prefix) for prefix in managed_prefixes):
                    continue

                delete_result = subprocess.run(
                    ["ip", "link", "delete", iface],
                    capture_output=True,
                )
                if delete_result.returncode == 0:
                    removed.append(iface)

            if removed:
                print(self.t(
                    f"🧹 Interfaces huérfanas eliminadas: {', '.join(removed)}",
                    f"🧹 Removed stale interfaces: {', '.join(removed)}",
                ))
        except Exception as e:
            print(self.t(
                f"⚠️ No se pudo completar la limpieza inicial de interfaces: {e}",
                f"⚠️ Could not complete initial interface cleanup: {e}",
            ))

    def is_host_interface_ready(self, interface_name):
        """Validar que la interfaz del host esté activa y con IPv4"""
        try:
            result = subprocess.run(
                ["ip", "-o", "-4", "addr", "show", "dev", interface_name, "up"],
                capture_output=True,
                text=True,
                check=True,
            )
            return bool(result.stdout.strip())
        except Exception:
            return False

    def pick_host_interface(self):
        """Permitir al usuario seleccionar la interfaz principal"""
        interfaces = self.get_available_interfaces()
        if not interfaces:
            print(self.t(
                "❌ No se pudieron detectar interfaces de red disponibles",
                "❌ No available network interfaces were detected",
            ))
            return None

        print(self.t(
            "\n🌐 Selecciona la interfaz de red a usar:",
            "\n🌐 Select the network interface to use:",
        ))
        for idx, iface in enumerate(interfaces, 1):
            print(f"   {idx}. {iface}")

        while True:
            choice = input(self.t("\nNúmero de interfaz: ", "\nInterface number: ")).strip()
            if not choice.isdigit():
                print(self.t("❌ Ingresa un número válido", "❌ Enter a valid number"))
                continue

            index = int(choice)
            if 1 <= index <= len(interfaces):
                selected = interfaces[index - 1]
                print(self.t(
                    f"✅ Interfaz seleccionada: {selected}",
                    f"✅ Selected interface: {selected}",
                ))
                return selected

            print(self.t(
                f"❌ Elige un valor entre 1 y {len(interfaces)}",
                f"❌ Pick a value between 1 and {len(interfaces)}",
            ))

    def ask_target(self):
        """Solicitar objetivo al usuario (IP o dominio)"""
        while True:
            target = input(self.t(
                "\n🎯 Ingresa IP o dominio objetivo: ",
                "\n🎯 Enter target IP or domain: ",
            )).strip()
            if not target:
                print(self.t(
                    "❌ El objetivo no puede estar vacío",
                    "❌ Target cannot be empty",
                ))
                continue

            # Validación IP directa
            try:
                socket.inet_aton(target)
                return target
            except OSError:
                pass

            # Validación de dominio por resolución DNS
            try:
                resolved_ip = socket.gethostbyname(target)
                print(self.t(
                    f"✅ Dominio válido: {target} -> {resolved_ip}",
                    f"✅ Valid domain: {target} -> {resolved_ip}",
                ))
                return target
            except socket.gaierror:
                print(self.t(
                    "❌ Objetivo no válido. Usa una IP o dominio resoluble.",
                    "❌ Invalid target. Use an IP or resolvable domain.",
                ))

    def interactive_mode_menu(self):
        """Menú principal para seleccionar tipo de ejecución"""
        print(self.t("\n📋 MENÚ PRINCIPAL", "\n📋 MAIN MENU"))
        print(self.t(
            "   1. Modo clásico (múltiples interfaces)",
            "   1. Classic mode (multiple interfaces)",
        ))
        print(self.t(
            "   2. Modo ciclos (1 interfaz por ciclo)",
            "   2. Cycle mode (1 interface per cycle)",
        ))

        while True:
            selected_mode = input(self.t(
                "\nSelecciona modo (1/2): ",
                "\nSelect mode (1/2): ",
            )).strip()
            if selected_mode in ("1", "2"):
                return "classic" if selected_mode == "1" else "cycles"
            print(self.t(
                "❌ Opción inválida, usa 1 o 2",
                "❌ Invalid option, use 1 or 2",
            ))
    
    def create_virtual_interface(self, interface_name="veth_pen"):
        """Crear interfaz virtual usando veth pair y conectarla a la red del anfitrión"""
        try:
            full_name = f"{interface_name}0"
            peer_name = f"{interface_name}1"
            
            # --- INICIO DE LA LÓGICA PARA CONECTAR A LA RED DEL ANFITRIÓN ---
            # Determinar la interfaz de red principal del anfitrión
            host_main_interface = self.host_main_interface
            if not host_main_interface:
                print(self.t(
                    "❌ No se definió la interfaz de red principal",
                    "❌ Host main interface was not set",
                ))
                return None
            
            # Intentar obtener la IP de la interfaz principal del anfitrión
            host_ip_cmd = f"ip -4 addr show {host_main_interface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}'"
            host_ip_result = subprocess.run(host_ip_cmd, shell=True, capture_output=True, text=True)
            host_ip = host_ip_result.stdout.strip()

            # Intentar obtener la máscara de subred (CIDR) de la interfaz principal del anfitrión
            host_cidr_cmd = f"ip -4 addr show {host_main_interface} | grep -oP '(?<=inet\\s)\\d+(\\.\\d+){{3}}/\\d+'"
            host_cidr_result = subprocess.run(host_cidr_cmd, shell=True, capture_output=True, text=True)
            host_cidr = host_cidr_result.stdout.strip()
            
            # Intentar obtener la puerta de enlace (gateway) de la interfaz principal del anfitrión
            gateway_ip_cmd = f"ip route | grep {host_main_interface} | grep default | awk '{{print $3}}'"
            gateway_result = subprocess.run(gateway_ip_cmd, shell=True, capture_output=True, text=True)
            gateway_ip = gateway_result.stdout.strip()

            if not host_ip or not host_cidr or not gateway_ip:
                print(self.t(
                    f"❌ No se pudo obtener la configuración de red de la interfaz principal '{host_main_interface}'.",
                    f"❌ Could not obtain host network configuration from '{host_main_interface}'.",
                ))
                print(self.t(
                    "   Asegúrate de que la interfaz esté activa y que 'host_main_interface' sea correcta.",
                    "   Ensure the interface is UP and 'host_main_interface' is correct.",
                ))
                print(self.t(
                    "   Intentando crear interfaz con IP aleatoria en rango privado (comportamiento anterior)...",
                    "   Falling back to random private IP allocation (legacy behavior)...",
                ))
                # Si no se puede obtener la configuración del anfitrión, se recurre al comportamiento anterior
                ip_addr = f"10.{random.randint(200,254)}.{random.randint(1,254)}.{random.randint(2,254)}/24"
                gateway_ip = f"10.{ip_addr.split('.')[1]}.{ip_addr.split('.')[2]}.1" # Gateway ficticio para la IP privada
                use_host_network = False
            else:
                # Calcular una IP aleatoria en la misma subred del anfitrión
                network_prefix = host_cidr.split('/')[0].rsplit('.', 1)[0] # Ej. 192.168.1.
                subnet_mask = host_cidr.split('/')[1]
                
                # Generar una IP aleatoria que no sea la del host ni la del gateway
                while True:
                    random_last_octet = random.randint(2, 254) # Evitar .0 y .1 (red y posible gateway)
                    virtual_ip_candidate = f"{network_prefix}.{random_last_octet}"
                    if virtual_ip_candidate != host_ip and virtual_ip_candidate != gateway_ip:
                        break
                
                ip_addr = f"{virtual_ip_candidate}/{subnet_mask}"
                use_host_network = True
            # --- FIN DE LA LÓGICA PARA CONECTAR A LA RED DEL ANFITRIÓN ---

            # Verificar si ya existe
            check_cmd = f"ip link show {full_name}"
            result = subprocess.run(check_cmd.split(), capture_output=True)
            if result.returncode == 0:
                print(self.t(
                    f"⚠️ Interfaz {full_name} ya existe, eliminándola...",
                    f"⚠️ Interface {full_name} already exists, deleting it...",
                ))
                subprocess.run(f"ip link delete {full_name}".split(), capture_output=True)
            
            # Crear par de interfaces veth
            cmd1 = f"ip link add {full_name} type veth peer name {peer_name}"
            subprocess.run(cmd1.split(), check=True, capture_output=True)
            
            # Asignar MAC aleatoria
            mac_addr = self.generate_random_mac()
            cmd2 = f"ip link set dev {full_name} address {mac_addr}"
            subprocess.run(cmd2.split(), check=True, capture_output=True)
            
            # Activar ambas interfaces del par
            cmd3a = f"ip link set {full_name} up"
            subprocess.run(cmd3a.split(), check=True, capture_output=True)
            
            cmd3b = f"ip link set {peer_name} up"
            subprocess.run(cmd3b.split(), check=True, capture_output=True)
            
            # Asignar IP
            cmd4 = f"ip addr add {ip_addr} dev {full_name}"
            subprocess.run(cmd4.split(), check=True, capture_output=True)
            
            # Agregar ruta por defecto
            if use_host_network:
                try:
                    cmd5 = f"ip route add default via {gateway_ip} dev {full_name} metric 100"
                    subprocess.run(cmd5.split(), capture_output=True)  # No check=True porque puede fallar
                    print(self.t(
                        f"   Ruta por defecto añadida via {gateway_ip}",
                        f"   Default route added via {gateway_ip}",
                    ))
                except Exception as e:
                    print(self.t(
                        f"⚠️ No se pudo añadir ruta por defecto para {full_name}: {e}",
                        f"⚠️ Could not add default route for {full_name}: {e}",
                    ))
            else:
                # Para IPs privadas aleatorias, la ruta por defecto es menos crítica para la conectividad externa
                print(self.t(
                    "   Usando IP privada aleatoria, no se añadió ruta por defecto específica.",
                    "   Using random private IP, no specific default route was added.",
                ))

            interface_info = {
                'name': full_name,
                'peer_name': peer_name,
                'mac': mac_addr,
                'ip': ip_addr,
                'created_at': datetime.now()
            }
            
            self.virtual_interfaces.append(interface_info)
            print(self.t(
                f"✅ Interfaz virtual creada: {full_name}",
                f"✅ Virtual interface created: {full_name}",
            ))
            print(f"   MAC: {mac_addr}")
            print(f"   IP: {ip_addr}")
            
            # Verificar que la interfaz esté funcionando
            time.sleep(0.5)
            verify_cmd = f"ip addr show {full_name}"
            verify_result = subprocess.run(verify_cmd.split(), capture_output=True, text=True)
            if "UP" in verify_result.stdout:
                print(self.t("   Estado: UP ✅", "   Status: UP ✅"))
            else:
                print(self.t("   Estado: DOWN ⚠️", "   Status: DOWN ⚠️"))
            
            return interface_info
            
        except subprocess.CalledProcessError as e:
            print(self.t(f"❌ Error creando interfaz: {e}", f"❌ Error creating interface: {e}"))
            print(self.t(
                f"   Detalles: {e.stderr.decode() if e.stderr else 'Sin detalles'}",
                f"   Details: {e.stderr.decode() if e.stderr else 'No details'}",
            ))
            return None
        except Exception as e:
            print(self.t(
                f"❌ Error inesperado en create_virtual_interface: {e}",
                f"❌ Unexpected error in create_virtual_interface: {e}",
            ))
            return None
    
    def delete_virtual_interface(self, interface_name):
        """Eliminar interfaz virtual y limpiar configuración"""
        try:
            # Buscar información de la interfaz
            interface_info = None
            for iface in self.virtual_interfaces:
                if iface['name'] == interface_name:
                    interface_info = iface
                    break
            
            if interface_info:
                # Limpiar reglas de iptables específicas (si se hubieran añadido)
                src_ip = interface_info['ip'].split('/')[0]
                nat_cmd = f"iptables -t nat -D POSTROUTING -s {src_ip}/32 -j MASQUERADE"
                subprocess.run(nat_cmd.split(), capture_output=True)
                
                # Eliminar bridge si existe (no se usa en este script, pero buena práctica)
                if 'bridge_name' in interface_info and interface_info['bridge_name']:
                    bridge_name = interface_info['bridge_name']
                    subprocess.run(f"ip link set dev {bridge_name} down".split(), capture_output=True)
                    subprocess.run(f"ip link delete {bridge_name}".split(), capture_output=True)
            
            # Eliminar rutas asociadas primero
            subprocess.run(f"ip route flush dev {interface_name}".split(), 
                         capture_output=True)
            
            # Eliminar la interfaz (esto también elimina su peer)
            cmd = f"ip link delete {interface_name}"
            subprocess.run(cmd.split(), check=True, capture_output=True)
            print(self.t(
                f"✅ Interfaz {interface_name} eliminada",
                f"✅ Interface {interface_name} removed",
            ))
            
            # Remover de la lista
            self.virtual_interfaces = [iface for iface in self.virtual_interfaces 
                                     if iface['name'] != interface_name]
        except subprocess.CalledProcessError as e:
            print(self.t(
                f"⚠️ Interfaz {interface_name} ya eliminada o no existe",
                f"⚠️ Interface {interface_name} was already removed or does not exist",
            ))
        except Exception as e:
            print(self.t(
                f"⚠️ Error limpiando interfaz {interface_name}: {e}",
                f"⚠️ Error cleaning interface {interface_name}: {e}",
            ))
    
    def cleanup_iptables(self):
        """Limpiar todas las reglas de iptables creadas"""
        try:
            # Limpiar reglas de NAT específicas de nuestras IPs
            for iface in self.virtual_interfaces:
                src_ip = iface['ip'].split('/')[0]
                nat_cmd = f"iptables -t nat -D POSTROUTING -s {src_ip}/32 -j MASQUERADE"
                subprocess.run(nat_cmd.split(), capture_output=True)
            print(self.t("✅ Reglas de iptables limpiadas", "✅ iptables rules cleaned"))
        except:
            pass
    
    def custom_ping(self, target, interface_info, count=4):
        """Enviar ping personalizado desde interfaz específica"""
        results = {
            'target': target,
            'interface': interface_info['name'],
            'mac': interface_info['mac'],
            'ip': interface_info['ip'].split('/')[0],
            'responses': [],
            'success_rate': 0
        }
        
        print(self.t(
            f"\n🔍 Enviando {count} pings a {target} desde {interface_info['name']}",
            f"\n🔍 Sending {count} pings to {target} from {interface_info['name']}",
        ))
        print(self.t(
            f"   Fuente MAC: {interface_info['mac']}",
            f"   Source MAC: {interface_info['mac']}",
        ))
        print(self.t(
            f"   Fuente IP: {interface_info['ip'].split('/')[0]}",
            f"   Source IP: {interface_info['ip'].split('/')[0]}",
        ))
        
        successful_pings = 0
        
        for i in range(count):
            try:
                # Método 1: Intentar ping del sistema primero
                ping_success = False
                start_time = time.time()
                
                # Usar ping del sistema con source IP específica
                src_ip = interface_info['ip'].split('/')[0]
                cmd = f"ping -S {src_ip} -c 1 -W 3 {target}"
                result = subprocess.run(cmd.split(), capture_output=True, text=True)
                
                if result.returncode == 0:
                    # Extraer tiempo real del ping
                    output = result.stdout
                    if "time=" in output:
                        try:
                            time_str = output.split("time=")[1].split()[0]
                            actual_rtt = float(time_str.replace("ms", ""))
                            print(self.t(
                                f"   Ping {i+1}: ✅ Respuesta de {target} - tiempo={actual_rtt:.2f}ms",
                                f"   Ping {i+1}: ✅ Reply from {target} - time={actual_rtt:.2f}ms",
                            ))
                            results['responses'].append({
                                'seq': i+1,
                                'rtt': actual_rtt,
                                'status': 'success',
                                'method': 'system_ping'
                            })
                            successful_pings += 1
                            ping_success = True
                        except:
                            print(self.t(
                                f"   Ping {i+1}: ✅ Respuesta de {target}",
                                f"   Ping {i+1}: ✅ Reply from {target}",
                            ))
                            results['responses'].append({
                                'seq': i+1,
                                'status': 'success',
                                'method': 'system_ping'
                            })
                            successful_pings += 1
                            ping_success = True
                
                # Si falla el ping del sistema, usar scapy
                if not ping_success:
                    scapy_result = self.scapy_ping_advanced(target, interface_info, i+1)
                    results['responses'].append(scapy_result)
                    if scapy_result['status'] == 'success':
                        successful_pings += 1
                        print(self.t(
                            f"   Ping {i+1}: ✅ Respuesta de {target} - tiempo={scapy_result.get('rtt', 'N/A'):.2f}ms (scapy)",
                            f"   Ping {i+1}: ✅ Reply from {target} - time={scapy_result.get('rtt', 'N/A'):.2f}ms (scapy)",
                        ))
                    elif scapy_result['status'] == 'reachable':
                        successful_pings += 1
                        print(self.t(
                            f"   Ping {i+1}: ✅ Host alcanzable (método alternativo)",
                            f"   Ping {i+1}: ✅ Host reachable (alternate method)",
                        ))
                    else:
                        print(self.t(
                            f"   Ping {i+1}: ❌ {scapy_result.get('error', 'Sin respuesta')}",
                            f"   Ping {i+1}: ❌ {scapy_result.get('error', 'No response')}",
                        ))
                
                # Delay aleatorio entre pings
                time.sleep(random.uniform(0.5, 1.5))
                
            except Exception as e:
                print(self.t(
                    f"   Ping {i+1}: ❌ Error - {e}",
                    f"   Ping {i+1}: ❌ Error - {e}",
                ))
                results['responses'].append({
                    'seq': i+1,
                    'status': 'error',
                    'error': str(e),
                    'method': 'exception'
                })
        
        results['success_rate'] = (successful_pings / count) * 100
        self.results.append(results)
        
        print(self.t(
            f"   Tasa de éxito: {results['success_rate']:.1f}%",
            f"   Success rate: {results['success_rate']:.1f}%",
        ))
        return results
    
    def scapy_ping_advanced(self, target, interface_info, seq):
        """Ping avanzado usando scapy con múltiples métodos"""
        src_ip = interface_info['ip'].split('/')[0]
        
        # Método 1: ICMP Echo Request
        try:
            packet = IP(dst=target, src=src_ip) / ICMP()
            start_time = time.time()
            response = sr1(packet, timeout=3, verbose=0)
            end_time = time.time()
            
            if response and response.haslayer(ICMP) and response[ICMP].type == 0:
                rtt = (end_time - start_time) * 1000
                return {
                    'seq': seq,
                    'rtt': rtt,
                    'status': 'success',
                    'method': 'scapy_icmp'
                }
        except:
            pass
        
        # Método 2: TCP SYN a puerto 80 (más sigiloso)
        try:
            tcp_packet = IP(dst=target, src=src_ip) / TCP(dport=80, flags="S")
            start_time = time.time()
            tcp_response = sr1(tcp_packet, timeout=3, verbose=0)
            end_time = time.time()
            
            if tcp_response and tcp_response.haslayer(TCP):
                rtt = (end_time - start_time) * 1000
                tcp_layer = tcp_response[TCP]
                
                if tcp_layer.flags & 0x12:  # SYN-ACK
                    return {
                        'seq': seq,
                        'rtt': rtt,
                        'status': 'reachable',
                        'method': 'scapy_tcp_syn',
                        'port_status': 'open'
                    }
                elif tcp_layer.flags & 0x04:  # RST
                    return {
                        'seq': seq,
                        'rtt': rtt,
                        'status': 'reachable',
                        'method': 'scapy_tcp_syn',
                        'port_status': 'closed'
                    }
        except Exception:
            pass
        
        # Método 3: UDP a puerto común
        try:
            udp_packet = IP(dst=target, src=src_ip) / UDP(dport=53)
            start_time = time.time()
            udp_response = sr1(udp_packet, timeout=2, verbose=0)
            end_time = time.time()
            
            if udp_response:
                rtt = (end_time - start_time) * 1000
                return {
                    'seq': seq,
                    'rtt': rtt,
                    'status': 'reachable',
                    'method': 'scapy_udp'
                }
        except Exception:
            pass
        
        return {
            'seq': seq,
            'status': 'timeout',
            'method': 'scapy_failed',
            'error': 'No response from any method'
        }
    
    def scan_multiple_targets(self, targets, interface_count=3):
        """Escanear múltiples objetivos con diferentes interfaces (modo clásico)"""
        print(self.t(
            f"\n🚀 Iniciando escaneo con {interface_count} interfaces virtuales",
            f"\n🚀 Starting scan with {interface_count} virtual interfaces",
        ))
        
        # Crear interfaces virtuales
        interfaces = []
        for i in range(interface_count):
            iface = self.create_virtual_interface(f"vpen{i}")
            if iface:
                interfaces.append(iface)
                time.sleep(1)  # Pausa entre creación de interfaces
        
        if not interfaces:
            print(self.t(
                "❌ No se pudieron crear interfaces virtuales",
                "❌ Could not create virtual interfaces",
            ))
            return
        
        # Escanear cada objetivo con cada interfaz
        for target in targets:
            print(self.t(
                f"\n🎯 Escaneando objetivo: {target}",
                f"\n🎯 Scanning target: {target}",
            ))
            for iface in interfaces:
                self.custom_ping(target, iface, count=self.default_ping_count)
                time.sleep(random.uniform(1, 3))  # Delay aleatorio
        
    def multiple_execution_cycles(self, targets, cycles, pings_per_target):
        """Ejecutar múltiples ciclos creando una interfaz diferente cada vez"""
        print(self.t(
            f"\n🔄 Iniciando {cycles} ciclos de ejecución",
            f"\n🔄 Starting {cycles} execution cycles",
        ))
        print(self.t(
            f"   Objetivos: {', '.join(targets)}",
            f"   Targets: {', '.join(targets)}",
        ))
        print(self.t(
            f"   Pings por objetivo: {pings_per_target}",
            f"   Pings per target: {pings_per_target}",
        ))
        print("="*60)
        
        all_cycle_results = []
        
        for cycle in range(1, cycles + 1):
            print(self.t(
                f"\n🚀 CICLO {cycle} de {cycles}",
                f"\n🚀 CYCLE {cycle} of {cycles}",
            ))
            print("-" * 40)
            
            # Crear una interfaz única para este ciclo
            interface_name = f"cycle{cycle:03d}"
            interface = self.create_virtual_interface(interface_name)
            
            if not interface:
                print(self.t(
                    f"❌ Error creando interfaz para ciclo {cycle}, saltando...",
                    f"❌ Error creating interface for cycle {cycle}, skipping...",
                ))
                continue
            
            cycle_results = {
                'cycle': cycle,
                'interface': interface,
                'targets_results': [],
                'start_time': datetime.now()
            }
            
            # Delay inicial aleatorio para cada ciclo
            initial_delay = random.uniform(2, 5)
            print(self.t(
                f"⏳ Esperando {initial_delay:.1f} segundos antes de comenzar...",
                f"⏳ Waiting {initial_delay:.1f} seconds before starting...",
            ))
            time.sleep(initial_delay)
            
            # Escanear cada objetivo con esta interfaz
            for target in targets:
                print(self.t(
                    f"\n🎯 Ciclo {cycle} - Escaneando: {target}",
                    f"\n🎯 Cycle {cycle} - Scanning: {target}",
                ))
                
                target_result = self.custom_ping(target, interface, pings_per_target)
                cycle_results['targets_results'].append(target_result)
                
                # Delay entre objetivos
                inter_target_delay = random.uniform(3, 8)
                if target != targets[-1]:  # No delay después del último objetivo
                    print(self.t(
                        f"⏳ Pausa de {inter_target_delay:.1f}s antes del próximo objetivo...",
                        f"⏳ Pause {inter_target_delay:.1f}s before next target...",
                    ))
                    time.sleep(inter_target_delay)
            
            cycle_results['end_time'] = datetime.now()
            cycle_results['duration'] = (cycle_results['end_time'] - cycle_results['start_time']).total_seconds()
            
            all_cycle_results.append(cycle_results)
            
            # Mostrar resumen del ciclo
            self.show_cycle_summary(cycle_results)
            
            # Limpiar la interfaz de este ciclo antes del siguiente
            if cycle < cycles:  # No limpiar en el último ciclo hasta el final
                print(self.t(
                    f"\n🧹 Limpiando interfaz del ciclo {cycle}...",
                    f"\n🧹 Cleaning interface for cycle {cycle}...",
                ))
                self.delete_virtual_interface(interface['name'])
                
                # Delay entre ciclos
                inter_cycle_delay = random.uniform(5, 12)
                print(self.t(
                    f"⏳ Pausa de {inter_cycle_delay:.1f}s antes del próximo ciclo...",
                    f"⏳ Pause {inter_cycle_delay:.1f}s before next cycle...",
                ))
                time.sleep(inter_cycle_delay)
        
        return all_cycle_results
    
    def show_cycle_summary(self, cycle_results):
        """Mostrar resumen de un ciclo individual"""
        cycle = cycle_results['cycle']
        interface = cycle_results['interface']
        duration = cycle_results['duration']
        
        print(self.t(
            f"\n📊 RESUMEN CICLO {cycle}",
            f"\n📊 CYCLE {cycle} SUMMARY",
        ))
        print(self.t(
            f"   Interfaz: {interface['name']} (MAC: {interface['mac']})",
            f"   Interface: {interface['name']} (MAC: {interface['mac']})",
        ))
        print(self.t(
            f"   Duración: {duration:.1f} segundos",
            f"   Duration: {duration:.1f} seconds",
        ))
        
        total_pings = 0
        successful_pings = 0
        
        for target_result in cycle_results['targets_results']:
            target_success = sum(1 for r in target_result['responses'] if r.get('status') == 'success')
            total_target_pings = len(target_result['responses'])
            success_rate = (total_target_pings / total_target_pings * 100) if total_target_pings > 0 else 0
            
            total_pings += total_target_pings
            successful_pings += target_success
            
            print(self.t(
                f"   {target_result['target']}: {success_rate:.1f}% éxito ({target_success}/{total_target_pings})",
                f"   {target_result['target']}: {success_rate:.1f}% success ({target_success}/{total_target_pings})",
            ))
        
        overall_success = (successful_pings / total_pings * 100) if total_pings > 0 else 0
        print(self.t(
            f"   Total: {overall_success:.1f}% éxito ({successful_pings}/{total_pings})",
            f"   Total: {overall_success:.1f}% success ({successful_pings}/{total_pings})",
        ))
    
    def show_final_summary(self, all_cycle_results):
        """Mostrar resumen final de todos los ciclos"""
        if not all_cycle_results:
            print(self.t("\n📊 No hay resultados para mostrar", "\n📊 No results to display"))
            return
        
        print("\n" + "="*70)
        print(self.t("🏁 RESUMEN FINAL DE TODOS LOS CICLOS", "🏁 FINAL SUMMARY OF ALL CYCLES"))
        print("="*70)
        
        total_cycles = len(all_cycle_results)
        total_duration = sum(cycle['duration'] for cycle in all_cycle_results)
        
        print(self.t(f"Ciclos ejecutados: {total_cycles}", f"Cycles executed: {total_cycles}"))
        print(self.t(
            f"Duración total: {total_duration:.1f} segundos ({total_duration/60:.1f} minutos)",
            f"Total duration: {total_duration:.1f} seconds ({total_duration/60:.1f} minutes)",
        ))
        print(self.t(
            f"Duración promedio por ciclo: {total_duration/total_cycles:.1f} segundos",
            f"Average duration per cycle: {total_duration/total_cycles:.1f} seconds",
        ))
        
        # Estadísticas por objetivo
        target_stats = {}
        interface_stats = []
        
        for cycle_result in all_cycle_results:
            # Recopilar estadísticas de interfaces
            interface_info = {
                'cycle': cycle_result['cycle'],
                'name': cycle_result['interface']['name'],
                'mac': cycle_result['interface']['mac'],
                'ip': cycle_result['interface']['ip'],
                'duration': cycle_result['duration']
            }
            interface_stats.append(interface_info)
            
            # Recopilar estadísticas por objetivo
            for target_result in cycle_result['targets_results']:
                target = target_result['target']
                if target not in target_stats:
                    target_stats[target] = {
                        'total_attempts': 0,
                        'total_successes': 0,
                        'cycles_tested': 0,
                        'avg_rtt': []
                    }
                
                target_stats[target]['cycles_tested'] += 1
                target_stats[target]['total_attempts'] += len(target_result['responses'])
                
                for response in target_result['responses']:
                    if response.get('status') == 'success':
                        target_stats[target]['total_successes'] += 1
                        if 'rtt' in response:
                            target_stats[target]['avg_rtt'].append(response['rtt'])
        
        # Mostrar estadísticas por objetivo
        print(self.t("\n📈 ESTADÍSTICAS POR OBJETIVO:", "\n📈 TARGET STATISTICS:"))
        for target, stats in target_stats.items():
            success_rate = (stats['total_successes'] / stats['total_attempts'] * 100) if stats['total_attempts'] > 0 else 0
            avg_rtt = sum(stats['avg_rtt']) / len(stats['avg_rtt']) if stats['avg_rtt'] else 0
            
            print(f"\n  🎯 {target}:")
            print(self.t(
                f"     Tasa de éxito: {success_rate:.1f}% ({stats['total_successes']}/{stats['total_attempts']})",
                f"     Success rate: {success_rate:.1f}% ({stats['total_successes']}/{stats['total_attempts']})",
            ))
            print(self.t(
                f"     Ciclos probados: {stats['cycles_tested']}",
                f"     Cycles tested: {stats['cycles_tested']}",
            ))
            if avg_rtt > 0:
                print(self.t(
                    f"     RTT promedio: {avg_rtt:.2f}ms",
                    f"     Average RTT: {avg_rtt:.2f}ms",
                ))
        
        # Mostrar información de interfaces usadas
        print(self.t("\n🔗 INTERFACES VIRTUALES UTILIZADAS:", "\n🔗 VIRTUAL INTERFACES USED:"))
        for iface in interface_stats:
            print(self.t(
                f"  Ciclo {iface['cycle']}: {iface['name']} - MAC: {iface['mac']} - IP: {iface['ip']} - Duración: {iface['duration']:.1f}s",
                f"  Cycle {iface['cycle']}: {iface['name']} - MAC: {iface['mac']} - IP: {iface['ip']} - Duration: {iface['duration']:.1f}s",
            ))
        
        # Detectar patrones interesantes
        print(self.t("\n🔍 ANÁLISIS DE PATRONES:", "\n🔍 PATTERN ANALYSIS:"))
        
        # Verificar si algún objetivo tuvo tasas de éxito muy variables
        for target, stats in target_stats.items():
            success_rate = (stats['total_successes'] / stats['total_attempts'] * 100) if stats['total_attempts'] > 0 else 0
            if 20 <= success_rate <= 80:
                print(self.t(
                    f"  ⚠️ {target}: Conectividad inconsistente ({success_rate:.1f}% éxito)",
                    f"  ⚠️ {target}: Inconsistent connectivity ({success_rate:.1f}% success)",
                ))
            elif success_rate == 0:
                print(self.t(
                    f"  ❌ {target}: Completamente inaccesible en todos los ciclos",
                    f"  ❌ {target}: Completely unreachable in all cycles",
                ))
            elif success_rate == 100:
                print(self.t(
                    f"  ✅ {target}: Completamente accesible en todos los ciclos",
                    f"  ✅ {target}: Fully reachable in all cycles",
                ))
        
        # Recomendar mejores configuraciones
        if len(interface_stats) > 1:
            fastest_cycle = min(interface_stats, key=lambda x: x['duration'])
            print(self.t(
                f"  🏃 Ciclo más rápido: #{fastest_cycle['cycle']} ({fastest_cycle['duration']:.1f}s)",
                f"  🏃 Fastest cycle: #{fastest_cycle['cycle']} ({fastest_cycle['duration']:.1f}s)",
            ))
        
        print(self.t("\n✅ Análisis completo finalizado", "\n✅ Full analysis completed"))
    
    def show_results_summary(self):
        """Mostrar resumen de resultados"""
        if not self.results:
            print(self.t("\n📊 No hay resultados para mostrar", "\n📊 No results to display"))
            return
        
        print("\n" + "="*60)
        print(self.t("📊 RESUMEN DE RESULTADOS", "📊 RESULTS SUMMARY"))
        print("="*60)
        
        for result in self.results:
            print(self.t(f"\nObjetivo: {result['target']}", f"\nTarget: {result['target']}"))
            print(self.t(
                f"Interfaz: {result['interface']} (MAC: {result['mac']})",
                f"Interface: {result['interface']} (MAC: {result['mac']})",
            ))
            print(self.t(
                f"Tasa de éxito: {result['success_rate']:.1f}%",
                f"Success rate: {result['success_rate']:.1f}%",
            ))
            
            if result['success_rate'] > 0:
                successful_responses = [r for r in result['responses'] if r.get('rtt')]
                if successful_responses:
                    avg_rtt = sum(r['rtt'] for r in successful_responses) / len(successful_responses)
                    print(self.t(f"RTT promedio: {avg_rtt:.2f}ms", f"Average RTT: {avg_rtt:.2f}ms"))
    
    def cleanup(self):
        """Limpiar interfaces virtuales creadas y configuración"""
        if self.cleanup_done:
            return

        print(self.t(
            f"\n🧹 Limpiando {len(self.virtual_interfaces)} interfaces virtuales...",
            f"\n🧹 Cleaning {len(self.virtual_interfaces)} virtual interfaces...",
        ))
        
        # Limpiar iptables primero
        self.cleanup_iptables()
        
        # Eliminar interfaces
        for iface in self.virtual_interfaces.copy():
            self.delete_virtual_interface(iface['name'])
        
        self.cleanup_done = True
        print(self.t("✅ Limpieza completada", "✅ Cleanup completed"))
    
    def list_interfaces(self):
        """Mostrar interfaces virtuales activas"""
        if not self.virtual_interfaces:
            print(self.t("No hay interfaces virtuales activas", "No active virtual interfaces"))
            return
            
        print(self.t(
            f"\n🔗 Interfaces virtuales activas ({len(self.virtual_interfaces)}):",
            f"\n🔗 Active virtual interfaces ({len(self.virtual_interfaces)}):",
        ))
        for iface in self.virtual_interfaces:
            print(f"  {iface['name']} - MAC: {iface['mac']} - IP: {iface['ip']}")


def install_signal_handlers(tool):
    """Instalar manejadores para limpiar interfaces al cerrar o suspender"""

    def _handle_shutdown(signum, _frame):
        try:
            signal_name = signal.Signals(signum).name
        except Exception:
            signal_name = str(signum)

        print(tool.t(
            f"\n⚠️ Señal {signal_name} recibida. Limpiando recursos...",
            f"\n⚠️ Signal {signal_name} received. Cleaning resources...",
        ))
        tool.cleanup()

        if signum == signal.SIGTSTP:
            print(tool.t(
                "ℹ️ Ctrl+Z detectado: el proceso se cerrará para evitar interfaces huérfanas.",
                "ℹ️ Ctrl+Z detected: process will exit to avoid orphan interfaces.",
            ))

        sys.exit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGQUIT, signal.SIGTSTP):
        signal.signal(sig, _handle_shutdown)

def main():
    parser = argparse.ArgumentParser(description='Virtual Network Interface Pentesting Tool')
    parser.add_argument('-t', '--targets', nargs='+', default=['8.8.8.8'], 
                        help='Objetivos/Targets (default: 8.8.8.8)')
    parser.add_argument('-i', '--interfaces', type=int, default=2,
                        help='Interfaces virtuales/Virtual interfaces (classic mode)')
    parser.add_argument('-c', '--count', type=int, default=3,
                        help='Pings por objetivo/Pings per target (default: 3)')
    parser.add_argument('--cycles', type=int, 
                        help='Número de ciclos/Number of cycles')
    parser.add_argument('--interactive', action='store_true',
                        help='Modo interactivo/Interactive mode')
    parser.add_argument('--mode', choices=['classic', 'cycles'],
                        help='Seleccionar modo/Select mode (classic or cycles)')
    parser.add_argument('--host-interface',
                        help='Interfaz de host/Host interface (e.g. wlan0, eth0)')
    parser.add_argument('--lang', choices=['es', 'en'],
                        help='Idioma/Language: es or en')
    
    args = parser.parse_args()
    
    tool = VirtualNetworkTool()
    
    try:
        if args.lang:
            tool.language = args.lang

        if not args.lang:
            tool.choose_language()

        print(tool.t(
            "🔧 Herramienta de Pentesting con Interfaces Virtuales",
            "🔧 Virtual Network Interface Pentesting Tool",
        ))
        print("=" * 50)
        
        tool.check_privileges()
        tool.cleanup_stale_virtual_interfaces()
        install_signal_handlers(tool)

        run_mode = args.mode

        if args.interactive or not run_mode:
            run_mode = tool.interactive_mode_menu()

            selected_iface = tool.pick_host_interface()
            if not selected_iface:
                print(tool.t(
                    "❌ No fue posible seleccionar interfaz de red",
                    "❌ Could not select a network interface",
                ))
                return
            tool.host_main_interface = selected_iface

            selected_target = tool.ask_target()
            args.targets = [selected_target]

            while True:
                try:
                    args.count = int(input(tool.t(
                        "\n📶 Pings por objetivo (1-10): ",
                        "\n📶 Pings per target (1-10): ",
                    )).strip())
                    if 1 <= args.count <= 10:
                        break
                    print(tool.t("❌ Debe estar entre 1 y 10", "❌ Must be between 1 and 10"))
                except ValueError:
                    print(tool.t("❌ Ingresa un número válido", "❌ Enter a valid number"))

            if run_mode == 'classic':
                while True:
                    try:
                        args.interfaces = int(input(tool.t(
                            "\n🔗 Número de interfaces virtuales (1-10): ",
                            "\n🔗 Number of virtual interfaces (1-10): ",
                        )).strip())
                        if 1 <= args.interfaces <= 10:
                            break
                        print(tool.t("❌ Debe estar entre 1 y 10", "❌ Must be between 1 and 10"))
                    except ValueError:
                        print(tool.t("❌ Ingresa un número válido", "❌ Enter a valid number"))
            else:
                while True:
                    try:
                        args.cycles = int(input(tool.t(
                            "\n🔄 Número de ciclos (1-50): ",
                            "\n🔄 Number of cycles (1-50): ",
                        )).strip())
                        if 1 <= args.cycles <= 50:
                            break
                        print(tool.t("❌ Debe estar entre 1 y 50", "❌ Must be between 1 and 50"))
                    except ValueError:
                        print(tool.t("❌ Ingresa un número válido", "❌ Enter a valid number"))
        else:
            tool.host_main_interface = args.host_interface
            if not tool.host_main_interface:
                print(tool.t(
                    "❌ Debes indicar la interfaz con --host-interface cuando uses --mode",
                    "❌ You must set --host-interface when using --mode",
                ))
                return

        if not tool.is_host_interface_ready(tool.host_main_interface):
            print(tool.t(
                f"❌ La interfaz '{tool.host_main_interface}' no está activa o no tiene IPv4.",
                f"❌ Interface '{tool.host_main_interface}' is down or has no IPv4.",
            ))
            print(tool.t(
                "   Usa una interfaz UP con IPv4 (por ejemplo, wlan0).",
                "   Use an UP interface with IPv4 (for example, wlan0).",
            ))
            return

        print(tool.t("\n✅ Configuración seleccionada:", "\n✅ Selected configuration:"))
        print(tool.t(
            f"   Modo: {'Clásico' if run_mode == 'classic' else 'Ciclos'}",
            f"   Mode: {'Classic' if run_mode == 'classic' else 'Cycles'}",
        ))
        print(tool.t(
            f"   Interfaz host: {tool.host_main_interface}",
            f"   Host interface: {tool.host_main_interface}",
        ))
        print(tool.t(
            f"   Objetivo: {', '.join(args.targets)}",
            f"   Target: {', '.join(args.targets)}",
        ))
        print(tool.t(
            f"   Pings por objetivo: {args.count}",
            f"   Pings per target: {args.count}",
        ))
        tool.default_ping_count = args.count
        if run_mode == 'classic':
            print(tool.t(
                f"   Interfaces virtuales: {args.interfaces}",
                f"   Virtual interfaces: {args.interfaces}",
            ))
        else:
            print(tool.t(f"   Ciclos: {args.cycles}", f"   Cycles: {args.cycles}"))
        
        # Modo ciclos múltiples
        if run_mode == 'cycles':
            cycles = args.cycles if args.cycles else 1

            # Ejecutar ciclos múltiples
            print(tool.t(
                f"\n🚀 Iniciando {cycles} ciclos de ejecución...",
                f"\n🚀 Starting {cycles} execution cycles...",
            ))
            all_results = tool.multiple_execution_cycles(args.targets, cycles, args.count)
            
            # Mostrar resumen final
            tool.show_final_summary(all_results)
            
        else:
            # Modo clásico (compatibilidad hacia atrás)
            print(tool.t(
                "\n📡 MODO CLÁSICO - Múltiples interfaces simultáneas",
                "\n📡 CLASSIC MODE - Multiple simultaneous interfaces",
            ))
            tool.scan_multiple_targets(args.targets, args.interfaces)
            tool.show_results_summary()
        
    except KeyboardInterrupt:
        print(tool.t("\n\n⚠️ Interrumpido por el usuario", "\n\n⚠️ Interrupted by user"))
    except Exception as e:
        print(tool.t(f"\n❌ Error inesperado: {e}", f"\n❌ Unexpected error: {e}"))
        import traceback
        traceback.print_exc()
    finally:
        # Limpiar interfaces
        tool.cleanup()
        print(tool.t("\n✅ Herramienta finalizada", "\n✅ Tool finished"))

if __name__ == "__main__":
    main()
