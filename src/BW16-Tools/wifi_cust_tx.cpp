#include "wifi_cust_tx.h"

/*
 * 发送一个指定长度的原始802.11帧
 * 该帧必须是有效的，且序列号为0（将会自动设置）
 * 帧校验序列会自动添加，不需要包含在长度中
 * @param frame 指向原始帧的指针
 * @param size 帧的大小
*/
void wifi_tx_raw_frame(void* frame, size_t length) {
  void *ptr = (void *)**(uint32_t **)((uint8_t*)rltk_wlan_info + 0x10);
  void *frame_control = alloc_mgtxmitframe((uint8_t*)ptr + 0xae0);

  if (frame_control != 0) {
    // 更新帧属性
    update_mgntframe_attrib(ptr, (uint8_t*)frame_control + 8);
    // 清空帧控制数据区
    memset((void *)*(uint32_t *)((uint8_t*)frame_control + 0x80), 0, 0x68);
    // 获取帧数据指针并复制数据
    uint8_t *frame_data = (uint8_t *)*(uint32_t *)((uint8_t*)frame_control + 0x80) + 0x28;
    memcpy(frame_data, frame, length);
    // 设置帧长度
    *(uint32_t *)((uint8_t*)frame_control + 0x14) = length;
    *(uint32_t *)((uint8_t*)frame_control + 0x18) = length;
    // 发送帧
    dump_mgntframe(ptr, frame_control);
  }
}

/*
 * 在当前信道发送802.11解除认证帧
 * @param src_mac 包含发送者MAC地址的字节数组，必须为6字节
 * @param dst_mac 包含目标MAC地址的字节数组，或使用FF:FF:FF:FF:FF:FF进行广播
 * @param reason 符合802.11规范的原因码（可选）
*/
void wifi_tx_deauth_frame(void* src_mac, void* dst_mac, uint16_t reason) {
  DeauthFrame frame;
  // 设置源MAC地址
  memcpy(&frame.source, src_mac, 6);
  // 设置接入点MAC地址
  memcpy(&frame.access_point, src_mac, 6);
  // 设置目标MAC地址
  memcpy(&frame.destination, dst_mac, 6);
  // 设置解除认证原因
  frame.reason = reason;
  // 发送帧
  wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
}

/*
 * 在当前信道发送一个基本的802.11信标帧
 * @param src_mac 包含发送者MAC地址的字节数组，必须为6字节
 * @param dst_mac 包含目标MAC地址的字节数组，或使用FF:FF:FF:FF:FF:FF进行广播
 * @param ssid 以'\0'结尾的字符数组，表示SSID
*/
void wifi_tx_beacon_frame(void* src_mac, void* dst_mac, const char *ssid) {
  BeaconFrame frame;
  // 设置源MAC地址
  memcpy(&frame.source, src_mac, 6);
  // 设置接入点MAC地址
  memcpy(&frame.access_point, src_mac, 6);
  // 设置目标MAC地址
  memcpy(&frame.destination, dst_mac, 6);
  // 复制SSID并计算长度
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  // 发送帧（帧大小为基础大小38字节加上SSID长度）
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

size_t wifi_build_beacon_frame(void* src_mac, void* dst_mac, const char *ssid, BeaconFrame &out) {
  // 预构建用于复用的信标帧缓冲
  memcpy(&out.source, src_mac, 6);
  memcpy(&out.access_point, src_mac, 6);
  memcpy(&out.destination, dst_mac, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid[i] != '\0'; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  return 38 + out.ssid_length;
}

void wifi_tx_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid) {
  ProbeRespFrame frame;
  memcpy(&frame.source, src_mac, 6);
  memcpy(&frame.access_point, src_mac, 6);
  memcpy(&frame.destination, dst_mac, 6);
  frame.ssid_length = 0;
  for (int i = 0; ssid[i] != '\0'; i++) {
    frame.ssid[i] = ssid[i];
    frame.ssid_length++;
  }
  wifi_tx_raw_frame(&frame, 38 + frame.ssid_length);
}

size_t wifi_build_probe_resp_frame(void* src_mac, void* dst_mac, const char *ssid, ProbeRespFrame &out) {
  memcpy(&out.source, src_mac, 6);
  memcpy(&out.access_point, src_mac, 6);
  memcpy(&out.destination, dst_mac, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid[i] != '\0'; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  return 38 + out.ssid_length;
}

size_t wifi_build_auth_req(void* sta_mac, void* bssid, AuthReqFrame &out) {
  memcpy(&out.source, sta_mac, 6);
  memcpy(&out.destination, bssid, 6);
  memcpy(&out.bssid, bssid, 6);
  out.auth_algorithm = 0x0000; // Open System
  out.auth_sequence = 0x0001;
  out.status_code = 0x0000;
  return sizeof(AuthReqFrame);
}

void wifi_tx_auth_req(void* sta_mac, void* bssid) {
  AuthReqFrame frame;
  size_t len = wifi_build_auth_req(sta_mac, bssid, frame);
  wifi_tx_raw_frame(&frame, len);
}

size_t wifi_build_assoc_req(void* sta_mac, void* bssid, const char* ssid, AssocReqFrame &out) {
  memcpy(&out.source, sta_mac, 6);
  memcpy(&out.destination, bssid, 6);
  memcpy(&out.bssid, bssid, 6);
  out.ssid_length = 0;
  for (int i = 0; ssid && ssid[i] != '\0' && i < 32; i++) {
    out.ssid[i] = ssid[i];
    out.ssid_length++;
  }
  // 固定能力与监听间隔已在结构体中给定
  // 关联请求帧长度 = 24字节MAC头(此处由结构体前部近似) + 固定字段(4) + IE(2+len)
  // 我们结构体已线性布局，直接返回有效占用长度
  return sizeof(AssocReqFrame) - (32 - out.ssid_length);
}

void wifi_tx_assoc_req(void* sta_mac, void* bssid, const char* ssid) {
  AssocReqFrame frame;
  size_t len = wifi_build_assoc_req(sta_mac, bssid, ssid, frame);
  wifi_tx_raw_frame(&frame, len);
}


