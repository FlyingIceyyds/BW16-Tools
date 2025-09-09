#ifndef WEB_CONFIG_H
#define WEB_CONFIG_H

// Web UI配置
#define WEB_UI_SSID "BW16-WebUI"        // AP的SSID名称
#define WEB_UI_PASSWORD "1234567890"     // AP的密码（至少8位）
#define WEB_UI_CHANNEL 1                 // AP的信道
#define WEB_UI_MAX_CONNECTIONS 4         // 最大连接数
#define WEB_SERVER_PORT 80               // Web服务器端口

// Web Test 配置（开放式SSID，无密码）
#define WEB_TEST_SSID "BW16-WebTest"    // 测试AP的SSID名称（无密码）
#define WEB_TEST_CHANNEL 1               // 测试AP的信道

// 配置说明：
// 1. SSID名称：显示在WiFi列表中的网络名称
// 2. 密码：连接AP时需要的密码
// 3. 信道：AP工作的WiFi信道（1-13为2.4GHz，36+为5GHz）
// 4. 最大连接数：同时连接到AP的最大设备数量
// 5. Web服务器端口：HTTP服务的端口号

// 修改这些值来自定义你的Web UI设置
// 注意：密码必须至少8位，否则AP无法启动

#endif
