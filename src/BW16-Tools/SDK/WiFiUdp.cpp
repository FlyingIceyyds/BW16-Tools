/*
  WiFiUdp.cpp - Library for Arduino Wifi shield.
  Copyright (c) 2011-2014 Arduino LLC.  All right reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include <string.h>
#include "server_drv.h"
#include "wifi_drv.h"
#include "WiFi.h"
#include "WiFiUdp.h"
#include "WiFiClient.h"
#include "WiFiServer.h"

#ifdef __cplusplus
extern "C" {
    extern int rtl_printf(const char *fmt, ...);
}
#endif

/* Constructor */
WiFiUDP::WiFiUDP() : _sock(-1), _client_sock(-1) {}

/* Destructor */
WiFiUDP::~WiFiUDP() {
    stop();
}

/* Start WiFiUDP socket, listening at local port PORT */
uint8_t WiFiUDP::begin(uint16_t port) {
    //printf("\n\rWiFiUDP::begin port %d", port);
    if ((_port == port) && (_sock >= 0)) {
        return 1;
    }

    _port = port;
    _sock = serverDrv.startServer(port, UDP_MODE);

    if (_sock >= 0) {
        return 1;
    }
    return 0;
}

int WiFiUDP::connect(const char *host, uint16_t port) {
    IPAddress remote_addr;
    IPv6Address remote_addr_v6;

    if (getIPv6Status() == 0) {
        if (WiFi.hostByName(host, remote_addr)) {
            //return connect(remote_addr, port);
        }
    } else {
        //printf("\n\r[INFO]WiFiUDP.cpp: connect|hostByNameV6 \n\r");
        if (WiFi.hostByNamev6(host, remote_addr_v6)) {
            //printf("[INFO]WiFiUDP.cpp: connect v6 \n\r");
            //printf("[INFO]WiFiUDP.cpp: connect ipv6 %s\n\r", host);
            _sock = clientDrv.startClientV6(host, port, UDP_MODE);
        }

        // whether sock is connected
        if (_sock < 0) {
            _is_connected = false;
            return 0;
        } else {
            _is_connected = true;
            clientDrv.setSockRecvTimeout(_sock, recvTimeout);
        }

        return 1;
    }
    return 0;
}

/* return number of bytes available in the current packet,
   will return zero if parsePacket hasn't been called yet */
int WiFiUDP::available() {
    int ret;

    if (_sock >= 0) {
        ret = serverDrv.availData(_sock);
        if (ret > 0) {
            return ret;
        } else {
            return 0;
        }
    }
    return 0;
}

/* Release any resources being used by this WiFiUDP instance */
void WiFiUDP::stop() {
    if (_sock < 0) {
        return;
    }

    serverDrv.stopSocket(_sock);

    _sock = -1;
}

int WiFiUDP::beginPacket(const char *host, uint16_t port) {
    // Look up the host first
    int ret = 0;
    IPAddress remote_addr;
    if (WiFi.hostByName(host, remote_addr)) {
        return beginPacket(remote_addr, port);
    }
    return ret;
}

int WiFiUDP::beginPacket(IPAddress ip, uint16_t port) {
    peer_ip = ip;
    peer_port = port;

    if (_sock >= 0) {
        _client_sock = _sock;
    } else {
        _client_sock = serverDrv.startClient(ip, port, UDP_MODE);
    }

    if (_client_sock < 0) {
        return 0;
    } else {
        return 1;
    }
}

int WiFiUDP::endPacket() {
    if (_client_sock >= 0 && _client_sock != _sock) {
        serverDrv.stopSocket(_client_sock);
    }

    peer_ip = 0;
    peer_port = 0;
    _client_sock = -1;

    return true;
}

size_t WiFiUDP::write(uint8_t byte) {
    return write(&byte, 1);
}

size_t WiFiUDP::write(const uint8_t *buffer, size_t size) {
    writeImmediately(buffer, size);

    return size;
}

int WiFiUDP::writeImmediately(const uint8_t *buffer, size_t size) {
    _client_sock = 0;
    serverDrv.sendtoData(_client_sock, buffer, size, peer_ip, peer_port);

    return size;
}

int WiFiUDP::writeImmediately(const uint8_t *buffer, size_t size, uint32_t peer_ip, uint16_t peer_port) {
    _client_sock = 0;
    serverDrv.sendtoData(_client_sock, buffer, size, peer_ip, peer_port);

    return size;
}

int WiFiUDP::parsePacket() {
    return available();
}

int WiFiUDP::read() {
    int ret;
    uint8_t b;

    ret = serverDrv.getData(_sock, &b);
    if (ret == 1) {
        return b;
    } else {
        return ret;
    }
}

int WiFiUDP::read(unsigned char *buffer, size_t len) {

    return serverDrv.getDataBuf(_sock, buffer, len);
}

int WiFiUDP::peek() {
    uint8_t b;
    if (!available()) {
        return -1;
    }
    serverDrv.getData(_sock, &b, 1);

    return b;
}

void WiFiUDP::flush() {
    while((read() > 0));
}

IPAddress WiFiUDP::remoteIP() {
    uint32_t _remoteIp;
    uint16_t _remotePort;

    serverDrv.getRemoteData(_sock, &_remoteIp, &_remotePort);

    IPAddress ip(_remoteIp);
    return ip;
}

uint16_t WiFiUDP::remotePort() {
    uint32_t _remoteIp;
    uint16_t _remotePort;

    serverDrv.getRemoteData(_sock, &_remoteIp, &_remotePort);

    return _remotePort;
}

// extend API by RTK
void WiFiUDP::setRecvTimeout(int timeout) {
    if (_sock >= 0) {
        serverDrv.setSockRecvTimeout(_sock, timeout);
    }
}

// IPv6 related
int WiFiUDP::enableIPv6() {
    return serverDrv.enableIPv6();
}

int WiFiUDP::getIPv6Status() {
    return serverDrv.getIPv6Status();
}

void WiFiUDP::UDPServerv6(void) {
    serverDrv.setIPv6UDPServer();
}
