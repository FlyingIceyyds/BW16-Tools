/*
  WiFi.cpp - Library for Arduino Wifi shield.
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

#include "WiFi.h"

#include <inttypes.h>

#include "wifi_drv.h"
#include "wiring.h"

WiFiClass::WiFiClass() {}

WiFiClass::~WiFiClass() {}

void WiFiClass::init() {
    WiFiDrv::wifiDriverInit();
}

char* WiFiClass::firmwareVersion() {
    return WiFiDrv::getFwVersion();
}

int WiFiClass::begin(char* ssid) {
    uint8_t status = WL_IDLE_STATUS;

    arduino_wifi_mode_check = arduino_wifi_mode_check| 0x01;

    WiFiDrv::wifiDriverInit();

    if ((WiFiDrv::wifiSetNetwork(ssid, (strlen(ssid)))) != WL_FAILURE) {
        status = WiFiDrv::getConnectionStatus();
    } else {
        status = WL_CONNECT_FAILED;
    }
    return status;
}

int WiFiClass::begin(char* ssid, uint8_t key_idx, const char *key) {
    uint8_t status = WL_IDLE_STATUS;

    arduino_wifi_mode_check = arduino_wifi_mode_check | 0x01;

    WiFiDrv::wifiDriverInit();

    // set encryption key
    if (WiFiDrv::wifiSetKey(ssid, strlen(ssid), key_idx, key, strlen(key)) != WL_FAILURE) {
        status = WiFiDrv::getConnectionStatus();
    } else {
        status = WL_CONNECT_FAILED;
    }
    return status;
}

int WiFiClass::begin(char* ssid, const char *passphrase) {
    uint8_t status = WL_IDLE_STATUS;

    arduino_wifi_mode_check = arduino_wifi_mode_check | 0x01;

    WiFiDrv::wifiDriverInit();

    // set passphrase
    if (WiFiDrv::wifiSetPassphrase(ssid, strlen(ssid), passphrase, strlen(passphrase))!= WL_FAILURE) {
         status = WiFiDrv::getConnectionStatus();
    } else {
        status = WL_CONNECT_FAILED;
    }
    return status;
}

void WiFiClass::enableConcurrent(void) {
    arduino_wifi_mode_check = arduino_wifi_mode_check | 0x11;
}

int WiFiClass::disconnect() {
    return WiFiDrv::disconnect();
}

uint8_t* WiFiClass::macAddress(uint8_t* mac) {
    uint8_t* _mac = WiFiDrv::getMacAddress();
    memcpy(mac, _mac, WL_MAC_ADDR_LENGTH);
    return mac;
}

IPAddress WiFiClass::localIP(uint8_t interface) {
    IPAddress ret;
    WiFiDrv::getIpAddress(ret, interface);
    return ret;
}

void WiFiClass::printLocalIPv6() {
    WiFiDrv::getIpv6Address();
}

IPAddress WiFiClass::subnetMask(uint8_t interface) {
    IPAddress ret;
    WiFiDrv::getSubnetMask(ret, interface);
    return ret;
}

IPAddress WiFiClass::gatewayIP(uint8_t interface) {
    IPAddress ret;
    WiFiDrv::getGatewayIP(ret, interface);
    return ret;
}

char* WiFiClass::SSID() {
    return WiFiDrv::getCurrentSSID();
}

uint8_t* WiFiClass::BSSID(uint8_t* bssid) {
    uint8_t* _bssid = WiFiDrv::getCurrentBSSID();
    memcpy(bssid, _bssid, WL_MAC_ADDR_LENGTH);
    return bssid;
}

int32_t WiFiClass::RSSI() {
    return WiFiDrv::getCurrentRSSI();
}

uint8_t WiFiClass::encryptionType() {
    return WiFiDrv::getCurrentEncryptionType();
}

int8_t WiFiClass::scanNetworks() {
    uint8_t attempts = 10;
    uint8_t numOfNetworks = 0;

    if (WiFiDrv::startScanNetworks() == WL_FAILURE) {
        return WL_FAILURE;
    }

    do {
         delay(2000);
         numOfNetworks = WiFiDrv::getScanNetworks();
    } while ((numOfNetworks == 0) && (--attempts > 0));
    return numOfNetworks;
}

char* WiFiClass::SSID(uint8_t networkItem) {
    return WiFiDrv::getSSIDNetworks(networkItem);
}

int32_t WiFiClass::RSSI(uint8_t networkItem) {
    return WiFiDrv::getRSSINetworks(networkItem);
}

uint8_t WiFiClass::encryptionType(uint8_t networkItem) {
    return WiFiDrv::getEncTypeNetworks(networkItem);
}

uint32_t WiFiClass::encryptionTypeEx(uint8_t networkItem) {
    return WiFiDrv::getEncTypeNetworksEx(networkItem);
}

uint8_t WiFiClass::status() {
    return WiFiDrv::getConnectionStatus();
}

int WiFiClass::hostByName(const char* aHostname, IPAddress& aResult) {
    return WiFiDrv::getHostByName(aHostname, aResult);
}

int WiFiClass::hostByNamev6(const char* aHostname, IPv6Address& aResult) {
    printf("[INFO]wifi.cpp: hostByNamev6()\n\r");
    return WiFiDrv::getHostByNamev6(aHostname, aResult);
}

int WiFiClass::apbegin(char* ssid, char* channel, uint8_t hidden_ssid) {
    uint8_t status = WL_IDLE_STATUS;
    arduino_wifi_mode_check = arduino_wifi_mode_check | 0x10;
    WiFiDrv::wifiDriverInit();

    if ((WiFiDrv::apSetNetwork(ssid, strlen(ssid))) != WL_FAILURE) {
        WiFiDrv::apSetChannel(channel);
        if ((WiFiDrv::apActivate(hidden_ssid)) != WL_FAILURE) {
            status = WL_CONNECTED;
        } else {
            status = WL_CONNECT_FAILED;
        }
    } else {
        status = WL_CONNECT_FAILED;
    }

    return status;
}

int WiFiClass::apbegin(char* ssid, char* password, char* channel, uint8_t hidden_ssid) {
    uint8_t status = WL_IDLE_STATUS;
    arduino_wifi_mode_check = arduino_wifi_mode_check | 0x10;
    WiFiDrv::wifiDriverInit();

    // Allow open AP via this overload by redirecting when password is NULL or empty
    if (password == NULL || password[0] == '\0') {
        return apbegin(ssid, channel, hidden_ssid);
    }

    if ((WiFiDrv::apSetNetwork(ssid, strlen(ssid))) != WL_FAILURE) {
        if ((WiFiDrv::apSetPassphrase(password, strlen(password))) != WL_FAILURE) {
            WiFiDrv::apSetChannel(channel);
            if (WiFiDrv::apActivate(hidden_ssid) != WL_FAILURE) {
                status = WL_CONNECTED;
            } else {
                status = WL_CONNECT_FAILED;
            }
        } else {
            status = WL_CONNECT_FAILED;
        }
    } else {
        status = WL_CONNECT_FAILED;
    }
    return status;
}

int WiFiClass::disablePowerSave() {
    return WiFiDrv::disablePowerSave();
}

void WiFiClass::config(IPAddress local_ip) {
    WiFiDrv::config(1, local_ip, IPAddress(0, 0, 0, 0), IPAddress(0, 0, 0, 0));
}

void WiFiClass::config(IPAddress local_ip, IPAddress dns_server) {
    setDNS(dns_server);
    config(local_ip);
}

void WiFiClass::config(IPAddress local_ip, IPAddress dns_server, IPAddress gateway) {
    setDNS(dns_server);
    WiFiDrv::config(2, local_ip, gateway, IPAddress(0, 0, 0, 0));
}

void WiFiClass::config(IPAddress local_ip, IPAddress dns_server, IPAddress gateway, IPAddress subnet) {
    setDNS(dns_server);
    WiFiDrv::config(3, local_ip, gateway, subnet);
}

void WiFiClass::setDNS(IPAddress dns_server1) {
    WiFiDrv::setDNS(1, dns_server1, IPAddress(0, 0, 0, 0));
}

void WiFiClass::setDNS(IPAddress dns_server1, IPAddress dns_server2) {
    WiFiDrv::setDNS(2, dns_server1, dns_server2);
}

void WiFiClass::setHostname(const char* hostname) {
    return WiFiDrv::setHostname(hostname);
}

const char* WiFiClass::getHostname() {
    return WiFiDrv::getHostname();
}

WiFiClass WiFi;
