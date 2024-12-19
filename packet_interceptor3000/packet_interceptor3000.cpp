#include <pcap.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <sstream>
#include <cstdint>
#include <chrono>
#include <vector>
#include <fstream>
#include <regex>
#include "colors.h"
using namespace std;

// Estructuras para cabeceras
struct eth_header {
    u_char dest_mac[6]; // MAC de destino (6 bytes)
    u_char src_mac[6];  // MAC de origen (6 bytes)
    u_short eth_type;   // Tipo de protocolo (IPv4: 0x0800, IPv6: 0x86DD)
};

// Cabecera IPv4
struct ipv4_header {
    u_char ver_ihl;       // Versión y longitud de cabecera (4 bits cada uno)
    u_char tos;           // Tipo de servicio (Quality of Service)
    u_short total_len;    // Longitud total del paquete (cabecera + datos)
    u_short id;           // Identificador del paquete (para fragmentación)
    u_short frag_off;     // Desplazamiento de fragmento y banderas
    u_char ttl;           // Tiempo de vida (TTL - Time To Live)
    u_char protocol;      // Protocolo de transporte (TCP: 6, UDP: 17)
    u_short checksum;     // Suma de verificación de la cabecera
    struct in_addr src_ip;  // Dirección IP de origen
    struct in_addr dest_ip; // Dirección IP de destino
};

// Cabecera IPv6
struct ipv6_header {
    uint32_t ver_traffic_class_flow;  // Versión, clase de tráfico y etiqueta de flujo (IPv6)
    u_short payload_length;           // Longitud de la carga útil (datos)
    u_char next_header;               // Próximo encabezado (TCP: 6, UDP: 17)
    u_char hop_limit;                 // Límite de saltos (TTL en IPv6)
    struct in6_addr src_ip;           // Dirección IP de origen (IPv6)
    struct in6_addr dest_ip;          // Dirección IP de destino (IPv6)
};

// Encabezado TCP
struct tcp_header {
    u_short src_port;    // Puerto de origen
    u_short dest_port;   // Puerto de destino
    u_int seq_num;       // Número de secuencia
    u_int ack_num;       // Número de acuse de recibo (ACK)
    u_char data_offset;  // Longitud de la cabecera (32 bits)
    u_char flags;        // Banderas de control (SYN, ACK, FIN, etc.)
    u_short window;      // Tamaño de la ventana de recepción
    u_short checksum;    // Suma de verificación del segmento TCP
    u_short urg_pointer; // Puntero de datos urgentes
};

// Encabezado UDP
struct udp_header {
    u_short src_port;    // Puerto de origen
    u_short dest_port;   // Puerto de destino
    u_short length;      // Longitud total del datagrama UDP (cabecera + datos)
    u_short checksum;    // Suma de verificación del datagrama UDP
};

struct packet_data {
    vector<u_char> content;
    int id;
    int length;
    string ipv;
    string src_ip;
    string dest_ip;
    string protocol;
    string src_mac;
    string dest_mac;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;

    // Constructor
    packet_data(const u_char* data, int len)
        : content(data, data + len), length(len), src_port(0), dest_port(0), seq_num(0), ack_num(0) {}
};

// Funcion para imprimir el tiempo
double calculate_time_relative(const struct timeval& start, const struct timeval& current);

// Para escribir el archivo .csv
void write_to_csv(ofstream& file, int packet_no, double time_relative, const string& src_ip, const string& dest_ip, const string& protocol, int length, int src_port, int dest_port);

string get_mac_address(const u_char* mac);

void printContent(const vector<u_char>& content);

// Menu de filtros
void filter_menu(pcap_t* handle);

int main() {
inicio:
    system("cls");
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup falló." << endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "Error al encontrar dispositivos: " << errbuf << endl;
        WSACleanup();
        return 1;
    }

    cout << "Dispositivos disponibles para captura: " << endl << endl;
    int i = 1;
    pcap_if_t* dev = alldevs;
    for (; dev != nullptr; dev = dev->next, i++) {
        cout << "[" << i << "] " << (dev->description ? dev->description : "Sin descripción") << endl;
    }
    cout << "[" << i << "] Salir" << endl;

    string choice = "";
    cout << endl << "Selecciona un dispositivo: ";
    cin >> choice;

    if (!isdigit(choice[0])) {
        cerr << "Entrada invalida. Por favor ingresa un numero valido." << endl;
        Sleep(1000);
        pcap_freealldevs(alldevs);
        WSACleanup();
        goto inicio;
    }

    int op = stoi(choice);
    if (op < 1 || op > i) {
        cerr << "Dispositivo seleccionado no es valido." << endl;
        Sleep(1000);
        pcap_freealldevs(alldevs);
        WSACleanup();
        goto inicio;
    }

    if (op == i) {
        cout << endl << "Adios!" << endl;
        return 0;
    }

    dev = alldevs;
    for (int j = 1; j < op && dev != nullptr; j++) {
        dev = dev->next;
    }

    pcap_t* handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        cerr << "Error al abrir dispositivo: " << errbuf << endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    PCAP_OPENFLAG_PROMISCUOUS; // promiscuous mode

    // Menu ////////////////////////////////////////////////////////////////
resetEtiq:
    system("cls");
    handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);

    string key = "";
    cout << endl << BLU << "Menu principal" << reset << endl;
    cout << endl << "[c] Para comenzar la captura";
    cout << endl << "[f] Para aplicar algun filtro";
    cout << endl << "[v] Para volver" << endl;
    cout << endl << "Elige una opcion: ";
    cin >> key;

    if (key.length() > 1) {
        cout << endl << "Opcion invalida, prueba de nuevo" << endl;
        Sleep(1000);
        goto resetEtiq;
    }
    if (key[0] == 'c') {
        goto captura;
    }
    else if (key[0] == 'f') {
        filter_menu(handle);
    }
    else if (key[0] == 'v') {
        goto inicio;
    }
    else {
        cout << endl << "Opcion invalida, prueba de nuevo" << endl;
        Sleep(1000);
        goto resetEtiq;
    }

    // COMIENZA LA CAPTURA ////////////////////////////////////////////////////////////////
captura:
    bool stop = false;
    vector<packet_data> captured_packets;

    time_t now = time(nullptr);
    char filename[64];
    struct tm time_info; // Estructura para almacenar la información de tiempo
    if (localtime_s(&time_info, &now) == 0) {
        strftime(filename, sizeof(filename), "captura_%Y%m%d_%H%M%S.csv", &time_info);
    }
    else {
        cerr << "Error al obtener el tiempo local." << endl;
        return 1;
    }

    ofstream csv_file(filename);
    if (!csv_file.is_open()) {
        cerr << "Error al abrir el archivo para guardar la captura." << endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res=0;
    int packet_no = 0;
    struct timeval start_time {};
    bool is_first_packet = true;
    double time_relative = 0;
    time_t last_packet_time = time(nullptr);
    const int NO_TRAFFIC_TIMEOUT = 10; // Tiempo máximo de espera sin tráfico

    // Encabezado para el area que muestra el trafico
    Sleep(1000);
    system("cls");
    cout << endl << "No.    Tiempo       Src IP                                  Dest IP                               Protocolo     Longitud" << endl;
    for (int i = 0; i < 120; i++) {
        cout << "-";
    }
    cout << endl;

    while ((res = pcap_next_ex(handle, &header, &packet)) >= 0 && !stop) {
        time_t current_time = time(nullptr);

        if (res == 0) {
            // Si no hay paquetes disponibles, verifica el tiempo transcurrido
            if (difftime(current_time, last_packet_time) >= NO_TRAFFIC_TIMEOUT) {
                stop = true;
                break;
            }
            continue; // Reintenta leer un paquete
        }

        last_packet_time = current_time; // Actualiza el tiempo del último paquete capturado

        packet_no++;
        packet_data pkt(packet, header->len);

        auto* eth = (struct eth_header*)packet;
        pkt.id = packet_no;
        pkt.src_mac = get_mac_address(eth->src_mac);
        pkt.dest_mac = get_mac_address(eth->dest_mac);

        // Si es IPv4
        if (ntohs(eth->eth_type) == 0x0800) {
            pkt.ipv = "ipv4";

            auto* ip = (struct ipv4_header*)(packet + sizeof(struct eth_header));
            auto* tcp = (struct tcp_header*)(packet + sizeof(struct eth_header) + (ip->ver_ihl & 0x0F) * 4);
            auto* udp = (struct udp_header*)(packet + sizeof(struct eth_header) + (ip->ver_ihl & 0x0F) * 4);

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip->src_ip), ip_str, INET_ADDRSTRLEN);
            pkt.src_ip = ip_str;
            inet_ntop(AF_INET, &(ip->dest_ip), ip_str, INET_ADDRSTRLEN);
            pkt.dest_ip = ip_str;

            if (ip->protocol == 6) {  // TCP
                pkt.protocol = "TCP";
                pkt.src_port = ntohs(tcp->src_port);
                pkt.dest_port = ntohs(tcp->dest_port);
                pkt.seq_num = ntohl(tcp->seq_num);
                pkt.ack_num = ntohl(tcp->ack_num);
            }
            else if (ip->protocol == 17) {  // UDP
                pkt.protocol = "UDP";
                pkt.src_port = ntohs(udp->src_port);
                pkt.dest_port = ntohs(udp->dest_port);
            }
            else {
                pkt.protocol = "Desconocido";
            }
        }

        // Si es IPv6
        else if (ntohs(eth->eth_type) == 0x86DD) {
            pkt.ipv = "ipv6";

            auto* ipv6 = (struct ipv6_header*)(packet + sizeof(struct eth_header));
            auto* tcp = (struct tcp_header*)(packet + sizeof(struct eth_header) + 40);
            auto* udp = (struct udp_header*)(packet + sizeof(struct eth_header) + 40);

            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ipv6->src_ip), ip_str, INET6_ADDRSTRLEN);
            pkt.src_ip = ip_str;
            inet_ntop(AF_INET6, &(ipv6->dest_ip), ip_str, INET6_ADDRSTRLEN);
            pkt.dest_ip = ip_str;

            if (ipv6->next_header == 6) {  // TCP
                pkt.protocol = "TCP";
                pkt.src_port = ntohs(tcp->src_port);
                pkt.dest_port = ntohs(tcp->dest_port);
                pkt.seq_num = ntohl(tcp->seq_num);
                pkt.ack_num = ntohl(tcp->ack_num);
            }
            else if (ipv6->next_header == 17) {  // UDP
                pkt.protocol = "UDP";
                pkt.src_port = ntohs(udp->src_port);
                pkt.dest_port = ntohs(udp->dest_port);
            }
            else {
                pkt.protocol = "Desconocido";
            }
        }

        // Si no es ninguno, es un protocolo desconocido en la capa de red
        else {
            pkt.ipv = "Desconocido";
        }

        captured_packets.push_back(pkt); // añadiendo paquete al vector de paquetes

        // Calcular tiempo relativo ///////////////////////////////////////////////////////////
        if (is_first_packet) {
            start_time = header->ts;
            is_first_packet = false;
        }
        time_relative = calculate_time_relative(start_time, header->ts);

        // Guardando en el archivo ////////////////////////////////////////////////////////////
        write_to_csv(csv_file, packet_no, time_relative, pkt.src_ip, pkt.dest_ip, pkt.protocol, pkt.length, pkt.src_port, pkt.dest_port);

        // Mostrando el trafico //////////////////////////////////////////////////////////////
        cout << left << setw(7) << packet_no; // id

        if (pkt.ipv == "ipv4" || pkt.ipv == "ipv6") {
            cout << fixed << setprecision(6) << setw(13) << time_relative; // tiempo relativo
            cout << left << setw(40) << pkt.src_ip; //ip origen
            cout << setw(40) << pkt.dest_ip; //ip destino

            if (pkt.protocol == "TCP") {
                cout << CYN << setw(14) << "TCP" << reset;
            }
            else if (pkt.protocol == "UDP") {
                cout << PRP << setw(14) << "UDP" << reset;
            }
            else {
                cout << RED << setw(14) << "Desconocido" << reset;
            }
            cout << reset << pkt.length;
        }
        else {
            cout << BG_RED << setw(40) << "Protocolo desconocido en la capa de red                                                                          " << reset;
        }

        // para detener la captura en cualquier momento
        if (_kbhit()) {
            char key = _getch();
            if (key == '\r') {
                stop = true;
                cout << endl << endl << ORG << "[ Se detuvo la captura ]" << reset << endl;
            }
        }

        cout << endl;

    } // while

    if (captured_packets.empty()) {
        cout << endl << ORG << "[ No hay trafico en esta interfaz. Elige otra. ]" << reset << endl << endl;
        csv_file.close();
        remove(filename);
        system("pause");
        goto inicio;
    }

    if (res == -1) {
        cerr << "Error en la captura: " << pcap_geterr(handle) << endl;
    }

    // Tras terminar la captura, el usuario tiene las siguientes opciones
regresar:
    string opcion = "";
    int id_packet = 0;
    bool flag = false;
    cout << endl << "Elige una opcion para continuar " << endl;
    cout << endl << "[p] Analizar un paquete en especifico";
    cout << endl << "[e] Exportar la informacion capturada en un archivo .csv y salir";
    cout << endl << "[x] Salir sin guardar";
    cout << endl << "[v] Volver al menu principal";
    cout << endl << "Input: ";
    cin >> opcion;

    if (opcion.length() > 1) {
        cout << endl << "Opcion invalida, prueba de nuevo" << endl;
        goto regresar;
    }

    if (opcion[0] != 'p' && opcion[0] != 'e' && opcion[0] != 'x' && opcion[0] != 'v') {
        cout << endl << "Opcion invalida, prueba de nuevo" << endl;
        goto regresar;
    }

    csv_file.close();
    if (opcion[0] == 'x') {
        remove(filename);
    }

    if (opcion[0] == 'v') {
        remove(filename);
        pcap_close(handle);
        goto resetEtiq;
    }
    else if (opcion[0] == 'e') {
        cout << endl << GRN << "Archivo guardado exitosamente!" << reset << endl;
    }

    while (opcion[0] == 'p') {
        cout << endl << "Ingresa el ID: ";
        cin >> id_packet;

        //for que recorra el vector que tiene los paquetes
        for (size_t i = 0; i < captured_packets.size(); i++) {
            const auto& pkt = captured_packets[i];

            if (id_packet == pkt.id) {
                flag = true;
                if (pkt.ipv == "ipv4") {
                    cout << endl << "------------------------------------------------------------------------------------------------------------------------" << endl;
                    cout << endl << GRN << "Internet Protocol Version 4" << reset;
                    cout << endl << "IP origen: "; cout << pkt.src_ip;
                    cout << endl << "IP destino "; cout << pkt.dest_ip;
                    cout << endl << "MAC origen: "; cout << pkt.src_mac;
                    cout << endl << "MAC destino: "; cout << pkt.dest_mac;

                    if (pkt.protocol == "UDP") {
                        cout << endl << "Puerto origen: " << pkt.src_port;
                        cout << endl << "Puerto destino: " << pkt.dest_port << endl;
                    }
                    else if (pkt.protocol == "TCP") {
                        cout << endl << "Puerto origen: " << pkt.src_port;
                        cout << endl << "Puerto destino: " << pkt.dest_port;
                        cout << endl << "Numero de secuencia: " << pkt.seq_num;
                        cout << endl << "Numero de acuse:  " << pkt.ack_num << endl;
                    }
                    else {
                        cout << endl << RED << "[ Protocolo desconocido en la capa de transporte ]" << reset << endl;
                    }
                }
                else if (pkt.ipv == "ipv6") {
                    cout << endl << "------------------------------------------------------------------------------------------------------------------------" << endl;
                    cout << endl << YEL << "Internet Protocol Version 6" << reset;
                    cout << endl << "IP origen: "; cout << pkt.src_ip;
                    cout << endl << "IP destino "; cout << pkt.dest_ip;
                    cout << endl << "MAC origen: "; cout << pkt.src_mac;
                    cout << endl << "MAC destino: "; cout << pkt.dest_mac;

                    if (pkt.protocol == "UDP") {
                        cout << endl << "Puerto origen: " << pkt.src_port;
                        cout << endl << "Puerto destino: " << pkt.dest_port << endl;

                    }
                    else if (pkt.protocol == "TCP") {
                        cout << endl << "Puerto origen: " << pkt.src_port;
                        cout << endl << "Puerto destino: " << pkt.dest_port;
                        cout << endl << "Numero de secuencia: " << pkt.seq_num;
                        cout << endl << "Numero de acuse:  " << pkt.ack_num << endl;

                    }
                    else {
                        cout << endl << RED << "[ Protocolo desconocido en la capa de transporte ]" << reset << endl;
                    }
                }
                else {
                    cout << endl << RED << "[ Protocolo desconocido en la capa de red ]" << reset << endl;
                }

                cout << endl;
                printContent(pkt.content);
                cout << endl << "------------------------------------------------------------------------------------------------------------------------" << endl;
                break;
            }
        }

        if (flag == false) {
            cout << endl << RED << "Error al buscar paquete" << reset << endl;
        }
        else {
            flag = false;
        }

        goto regresar;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    WSACleanup();

    return 0;
}

double calculate_time_relative(const struct timeval& start, const struct timeval& current) {
    double start_time = start.tv_sec + start.tv_usec / 1e6;
    double current_time = current.tv_sec + current.tv_usec / 1e6;
    return current_time - start_time;
}

void write_to_csv(ofstream& file, int packet_no, double time_relative, const string& src_ip, const string& dest_ip, const string& protocol, int length, int src_port, int dest_port) {
    file << dec << packet_no << ","
        << fixed << setprecision(6) << time_relative << ","
        << src_ip << ","
        << dest_ip << ","
        << protocol << ","
        << length << ","
        << src_port << ","
        << dest_port << endl;
}

string get_mac_address(const u_char* mac) {
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(mac_str);
}

void printContent(const vector<u_char>& content) {
    for (const auto& byte : content) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(byte) << " ";
    }
    cout << dec << setfill(' ') << endl; // Vuelve al formato decimal
}

void filter_menu(pcap_t* handle) {
x:
    struct bpf_program fp;
    string op = "", input = "", config = "", filter_exp = "";
    int opc = 0;
    system("cls");
    cout << endl << PRP << "Opciones para el filtrado: " << reset << endl;
    cout << endl << "[1] Por protocolo en la capa de red (IPv4/IPv6)";
    cout << endl << "[2] Por protocolo en la capa de transporte (TCP/UDP)";
    cout << endl << "[3] Por direccion IP";
    cout << endl << "[4] Por direccion MAC";
    cout << endl << "[5] Salir";
    cout << endl << "Elige una opcion: ";
    cin >> op;

    if (!(isdigit(op[0]))) {
        cout << endl << "Opcion de filtrado invalida, prueba de nuevo";
        Sleep(1500);
        goto x;
    }
    else {
        opc = stoi(op);
        if (opc <= 0 || opc > 5) {
            cout << endl << "Opcion de filtrado invalida, prueba de nuevo";
            Sleep(1500);
            goto x;
        }
    }

    system("cls");

    switch (opc) {
    case 1:
        input = "";
        filter_exp = "";
        cout << endl << "Ingresa el protocolo: ";
        cin >> input;

        if (input == "ipv4") {
            filter_exp = "ip";
        }
        else if (input == "ipv6") {
            filter_exp = "ip6";
        }
        else {
            cout << endl << "Expresion invalida, ingresa ipv4 / ipv6";
            Sleep(1500);
            goto x;
        }

        // Compilar el filtro
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Error al compilar el filtro: " << pcap_geterr(handle) << endl;
            return;
        }

        // Aplicar el filtro
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Error al aplicar el filtro: " << pcap_geterr(handle) << endl;
            pcap_freecode(&fp);
            return;
        }

        cout << "Filtro aplicado: " << filter_exp;
        pcap_freecode(&fp); // Liberar memoria asociada al filtro
        break;

    case 2:
        input = "";
        filter_exp = "";
        cout << endl << "Ingresa el protocolo: ";
        cin >> input;

        if (input == "tcp") {
            filter_exp = "tcp";
        }
        else if (input == "udp") {
            filter_exp = "udp";
        }
        else {
            cout << endl << "Expresion invalida, ingresa tcp / udp";
            Sleep(1500);
            goto x;
        }

        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Error al compilar el filtro: " << pcap_geterr(handle) << endl;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Error al aplicar el filtro: " << pcap_geterr(handle) << endl;
            pcap_freecode(&fp);
            return;
        }

        cout << "Filtro aplicado: " << filter_exp;
        pcap_freecode(&fp);
        break;

    case 3:
        input = "";
        config = "";
        filter_exp = "";
        cout << endl << "Ingresa direccion IP: ";
        cin >> input;

        if (!regex_match(input, regex(R"(^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$)")) &&
            !regex_match(input, regex(R"(^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$)"))) {
            cout << "Direccion IP invalida. Debe ser una direccion IPv4 o IPv6 valida." << endl;
            Sleep(1500);
            goto x;
        }

        cout << endl << "Define si la IP es [src] / [dest]: ";
        cin >> config;

        if (config == "src") {
            filter_exp = "src host " + input;
        }
        else if (config == "dest") {
            filter_exp = "dst host " + input;
        }
        else {
            cout << endl << "Configuración desconocida. Usa 'src' o 'dest'";
            Sleep(1500);
            goto x;
        }

        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Error al compilar el filtro: " << pcap_geterr(handle) << endl;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Error al aplicar el filtro: " << pcap_geterr(handle) << endl;
            pcap_freecode(&fp);
            return;
        }

        cout << "Filtro aplicado: " << filter_exp;
        pcap_freecode(&fp);
        break;

    case 4:
        input = "";
        config = "";
        filter_exp = "";
        cout << endl << "Ingresa la MAC: ";
        cin >> input;

        if (!regex_match(input, regex(R"(^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$)"))) {
            cout << "Direccion MAC invalida. Debe seguir el formato xx:xx:xx:xx:xx:xx." << endl;
            Sleep(1500);
            goto x;
        }

        cout << endl << "Define si la MAC es [src] / [dest]: ";
        cin >> config;

        if (config == "src") {
            filter_exp = "ether src " + input;
        }
        else if (config == "dest") {
            filter_exp = "ether dst " + input;
        }
        else {
            cout << endl << "Configuración desconocida. Usa 'src' o 'dest'";
            Sleep(1500);
            goto x;
        }

        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            cerr << "Error al compilar el filtro: " << pcap_geterr(handle) << endl;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Error al aplicar el filtro: " << pcap_geterr(handle) << endl;
            pcap_freecode(&fp);
            return;
        }

        cout << "Filtro aplicado: " << filter_exp;
        pcap_freecode(&fp);
        break;

    case 5:
        cout << endl << "Ningun filtro aplicado ";
        break;
    }

    Sleep(1500);
}

// Notas: 
// pcap_findalldevs encuentra todas las interfaces de captura disponibles, como tarjetas de red, adaptadores de red virtuales, etc.