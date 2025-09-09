#ifndef U8G2_ADAFRUIT_ADAPTER_H
#define U8G2_ADAFRUIT_ADAPTER_H

#include <Arduino.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>

// These are provided by BW16-Tools.ino
extern Adafruit_SSD1306 display;

// Minimal adapter exposing the subset of U8g2 API used by face module
class U8g2Adapter {
public:
  void setI2CAddress(uint8_t /*addr*/) {}
  void begin() {}

  void clearBuffer() { display.clearDisplay(); }
  void sendBuffer() { display.display(); }

  void setDrawColor(uint16_t color) { currentColor = color ? SSD1306_WHITE : SSD1306_BLACK; }

  void drawHLine(int16_t x, int16_t y, int16_t w) { display.drawFastHLine(x, y, w, currentColor); }
  void drawBox(int16_t x, int16_t y, int16_t w, int16_t h) { display.fillRect(x, y, w, h, currentColor); }
  void drawTriangle(int16_t x0, int16_t y0, int16_t x1, int16_t y1, int16_t x2, int16_t y2) {
    display.fillTriangle(x0, y0, x1, y1, x2, y2, currentColor);
  }

private:
  uint16_t currentColor = SSD1306_WHITE;
};

extern U8g2Adapter u8g2;

#endif


