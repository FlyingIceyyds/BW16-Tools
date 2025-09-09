#ifndef DEBUG_H
#define DEBUG_H

#include <Arduino.h>

//#define DEBUG  // 调试模式开关

// 设置调试串口波特率
#define DEBUG_BAUD 115200

#ifdef DEBUG
  // 如果定义了DEBUG，初始化串口通信
  #define DEBUG_SER_INIT() Serial.begin(DEBUG_BAUD);
  // 如果定义了DEBUG，输出调试信息
  #define DEBUG_SER_PRINT(...) Serial.print(__VA_ARGS__);
#else
  // 如果没有定义DEBUG，这些宏将不执行任何操作
  #define DEBUG_SER_PRINT(...)
  #define DEBUG_SER_INIT()
#endif

#endif
