#ifndef WIFI_CUST_TX
#define WIFI_CUST_TX

#include <Arduino.h>

// 类型定义
typedef uint8_t __u8;

// 必要的常量定义
#define WLAN0_NAME "wlan0"

// 紧凑打包并按4字节对齐整体实例，降低拷贝/访问的未对齐开销

// 定义解除认证帧的结构体
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xC0;      // 帧控制字段，设置为解除认证类型
  uint16_t duration = 0xFFFF;         // 持续时间字段
  uint8_t destination[6];             // 目标MAC地址
  uint8_t source[6];                  // 源MAC地址
  uint8_t access_point[6];            // 接入点MAC地址
  const uint16_t sequence_number = 0;  // 序列号
  uint16_t reason = 0x06;             // 解除认证原因码
} DeauthFrame;

// 定义支持802.11w的加密管理帧结构体
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xC0;      // 帧控制字段，设置为解除认证类型
  uint16_t duration = 0xFFFF;         // 持续时间字段
  uint8_t destination[6];             // 目标MAC地址
  uint8_t source[6];                  // 源MAC地址
  uint8_t access_point[6];            // 接入点MAC地址
  const uint16_t sequence_number = 0;  // 序列号
  uint16_t reason = 0x06;             // 解除认证原因码
  uint8_t mic[16];                    // 消息完整性检查码
  uint8_t key_replay_counter[8];      // 密钥重放计数器
} ProtectedDeauthFrame;

// 定义信标帧的结构体
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x80;      // 帧控制字段，设置为信标类型
  uint16_t duration = 0;              // 持续时间字段
  uint8_t destination[6];             // 目标MAC地址
  uint8_t source[6];                  // 源MAC地址
  uint8_t access_point[6];            // 接入点MAC地址
  const uint16_t sequence_number = 0;  // 序列号
  const uint64_t timestamp = 0;       // 时间戳
  uint16_t beacon_interval = 0x64;    // 信标间隔
  uint16_t ap_capabilities = 0x21;    // 接入点能力信息
  const uint8_t ssid_tag = 0;         // SSID标签
  uint8_t ssid_length = 0;            // SSID长度
  uint8_t ssid[255];                  // SSID内容
} BeaconFrame;

// 定义探测响应帧（最小可用字段，保持与Beacon类似的IE布局）
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x50;      // Type/Subtype: Probe Response
  uint16_t duration = 0;              // 持续时间
  uint8_t destination[6];             // 目标MAC（广播/任意）
  uint8_t source[6];                  // 源MAC（伪造的AP）
  uint8_t access_point[6];            // BSSID（同源MAC）
  const uint16_t sequence_number = 0; // 序列号
  const uint64_t timestamp = 0;       // 时间戳
  uint16_t beacon_interval = 0x64;    // 间隔
  uint16_t ap_capabilities = 0x21;    // 能力
  const uint8_t ssid_tag = 0;         // SSID标签
  uint8_t ssid_length = 0;            // SSID长度
  uint8_t ssid[255];                  // SSID内容
} ProbeRespFrame;

// 802.11 认证请求帧（Open System）最小字段
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0xB0;      // Type/Subtype: Authentication
  uint16_t duration = 0;
  uint8_t destination[6];             // BSSID/接入点
  uint8_t source[6];                  // STA MAC（伪造）
  uint8_t bssid[6];                   // BSSID
  const uint16_t sequence_number = 0;
  uint16_t auth_algorithm = 0x0000;   // Open System
  uint16_t auth_sequence = 0x0001;    // Seq 1: authentication request
  uint16_t status_code = 0x0000;      // 保持0
} AuthReqFrame;

// 802.11 关联请求帧（最小可用字段，固定能力+SSID IE + 支持速率IE 可省略）
typedef struct __attribute__((packed, aligned(4))) {
  uint16_t frame_control = 0x0000 | (0x0 << 2) | (0x0 << 4); // 占位，稍后由SDK填充也可直接0
  uint16_t duration = 0;
  uint8_t destination[6];             // BSSID
  uint8_t source[6];                  // STA MAC
  uint8_t bssid[6];                   // BSSID
  const uint16_t sequence_number = 0;
  uint16_t capability = 0x0431;       // 常见基本能力集
  uint16_t listen_interval = 0x000A;  // 10 TU
  // IE: SSID
  const uint8_t ssid_tag = 0x00;
  uint8_t ssid_length = 0;
  uint8_t ssid[32];
} AssocReqFrame;

// 从闭源库导入所需的C函数
// 注意：函数定义可能不是100%准确，因为在编译过程中类型信息会丢失
extern uint8_t* rltk_wlan_info;
extern "C" void* alloc_mgtxmitframe(void* ptr);
extern "C" void update_mgntframe_attrib(void* ptr, void* frame_control);
extern "C" int dump_mgntframe(void* ptr, void* frame_control);

// 外部函数声明 - 移除冲突的声明，使用SDK中的版本

// 函数声明
void wifi_tx_raw_frame(void* frame, size_t length);
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason = 0x06);
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid);
// 仅构建信标帧但不发送，返回帧长度，便于上层循环复用缓冲区进行突发发送
size_t wifi_build_beacon_frame(void* src_mac, void* dst_mac, const char *ssid, BeaconFrame &out);

// 构建/发送探测响应，便于上层突发重用
size_t wifi_build_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid, ProbeRespFrame &out);
void wifi_tx_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid);

// 新增：支持802.11w的加密管理帧函数
void wifi_tx_protected_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason, const uint8_t* mic, const uint8_t* replay_counter);
bool wifi_generate_pmf_mic(const uint8_t* frame, size_t frame_len, const uint8_t* key, uint8_t* mic);
bool wifi_attempt_pmf_attack(const uint8_t* bssid, const uint8_t* client_mac, uint8_t channel);

// 新增：构建并发送认证/关联请求
size_t wifi_build_auth_req(void* sta_mac, void* bssid, AuthReqFrame &out);
void wifi_tx_auth_req(void* sta_mac, void* bssid);
size_t wifi_build_assoc_req(void* sta_mac, void* bssid, const char* ssid, AssocReqFrame &out);
void wifi_tx_assoc_req(void* sta_mac, void* bssid, const char* ssid);



#endif
