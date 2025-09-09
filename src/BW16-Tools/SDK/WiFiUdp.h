/*
  WiFiUdp.h - Library for Arduino Wifi shield.
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

#ifndef WiFiUdp_h
#define WiFiUdp_h

#include "IPAddress.h"
#include "IPv6Address.h"
#include "server_drv.h"
#include "wifi_Udp.h"

#define UDP_TX_PACKET_MAX_SIZE 24

class WiFiUDP : public UDP {
    public:
        // Constructor
        WiFiUDP();

        // Destructor
        ~WiFiUDP();

        // initialize, start listening on specified port. Returns 1 if successful, 0 if there are no sockets available to use
        virtual uint8_t begin(uint16_t);

        virtual int connect(const char* host, uint16_t port);

        // Finish with the UDP socket
        virtual void stop();

        // Sending UDP packets
        // Start building up a packet to send to the remote host specific in ip and port
        // Returns 1 if successful, 0 if there was a problem with the supplied IP address or port
        virtual int beginPacket(IPAddress ip, uint16_t port);

        // Start building up a packet to send to the remote host specific in host and port
        // Returns 1 if successful, 0 if there was a problem resolving the hostname or port
        virtual int beginPacket(const char* host, uint16_t port);

        // Finish off this packet and send it
        // Returns 1 if the packet was sent successfully, 0 if there was an error
        virtual int endPacket();

        // Write a single byte into the packet
        virtual size_t write(uint8_t);

        // Write size bytes from buffer into the packet
        virtual size_t write(const uint8_t* buffer, size_t size);

        // Send packet immediately from buffer
        int writeImmediately(const uint8_t* buffer, size_t size);
        int writeImmediately(const uint8_t* buffer, size_t size, uint32_t peer_ip, uint16_t peer_port);

        // Start processing the next available incoming packet
        // Returns the size of the packet in bytes, or 0 if no packets are available
        virtual int parsePacket();

        // Number of bytes remaining in the current packet
        virtual int available();

        // Read a single byte from the current packet
        virtual int read();

        // Read up to len bytes from the current packet and place them into buffer
        // Returns the number of bytes read, or 0 if none are available
        virtual int read(unsigned char* buffer, size_t len);

        // Read up to len characters from the current packet and place them into buffer
        // Returns the number of characters read, or 0 if none are available
        virtual int read(char* buffer, size_t len) { return read((unsigned char*)buffer, len); };

        // Return the next byte from the current packet without moving on to the next byte
        virtual int peek();

        // Finish reading the current packet
        virtual void flush();

        // Return the IP address of the host who sent the current incoming packet
        virtual IPAddress remoteIP();

        // Return the port of the host who sent the current incoming packet
        virtual uint16_t remotePort();

        // extend API by RTK
        void setRecvTimeout(int timeout);

        // IPv6 related
        virtual int enableIPv6();
        virtual int getIPv6Status();
        virtual void UDPServerv6(void);

        friend class WiFiDrv;
        using Print::write;

    private:
        int _sock;  // socket ID
        int _client_sock;
        int recvTimeout;
        bool _is_connected;
        uint16_t _port;       // local port to listen on
        ServerDrv serverDrv;  // socket driver
        ServerDrv clientDrv;  // socket driver
        uint8_t data[DATA_LENTH];
        uint32_t peer_ip;
        uint32_t peer_port;
        uint32_t peer_ip_v6;
        uint32_t peer_port_v6;
};

#endif
