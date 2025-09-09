#ifndef WiFiServer_h
#define WiFiServer_h

#include "Server.h"
#include "server_drv.h"

class WiFiClient;

class WiFiServer : public Server {
    public:
        WiFiServer(uint16_t);
        WiFiServer(uint16_t, tProtMode);
        ~WiFiServer();

        virtual void begin();
        WiFiClient available(uint8_t* status = NULL);
        virtual int available(int server_fd);
        virtual uint8_t connected();
        virtual int recv(uint8_t* buf, size_t size);
        virtual size_t write(uint8_t b);
        virtual size_t write(const uint8_t* buf, size_t size);
        virtual void stop();
        virtual void end();
        virtual void close();
        virtual void setBlocking();
        // extend API from RTK
        virtual int setTimeout(int timeout);
        // IPv6 related
        int enableIPv6();
        int getIPv6Status();
        using Print::write;

    private:
        ServerDrv serverdrv;
        uint16_t _port;
        int _sock_ser;
        bool _is_connected;
        uint8_t data[DATA_LENTH];
        int recvTimeout;
        bool _is_blocked = false;
        tProtMode _portMode = TCP_MODE;
};

#endif
