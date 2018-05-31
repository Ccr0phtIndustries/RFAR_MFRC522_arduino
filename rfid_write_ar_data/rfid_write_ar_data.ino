/*
 * Write RFAR data to a MIFARE RFID card using a RFID-RC522 reader
 * Uses MFRC522 - Library to use ARDUINO RFID MODULE KIT 13.56 MHZ WITH TAGS SPI W AND R BY COOQROBOT. 
 * Follows the RFAV spec at ccr0pht.com
 * -----------------------------------------------------------------------------------------
 *             MFRC522      Arduino       Arduino   Arduino    Arduino          Arduino
 *             Reader/PCD   Uno/101       Mega      Nano v3    Leonardo/Micro   Pro Micro
 * Signal      Pin          Pin           Pin       Pin        Pin              Pin
 * -----------------------------------------------------------------------------------------
 * RST/Reset   RST          9             5         D9         RESET/ICSP-5     RST
 * SPI SS      SDA(SS)      10            53        D10        10               10
 * SPI MOSI    MOSI         11 / ICSP-4   51        D11        ICSP-4           16
 * SPI MISO    MISO         12 / ICSP-1   50        D12        ICSP-1           14
 * SPI SCK     SCK          13 / ICSP-3   52        D13        ICSP-3           15
 *
 * Hardware required:
 * Arduino e.g. Uno
 * PCD (Proximity Coupling Device): NXP MFRC522 Contactless Reader IC
 * PICC (Proximity Integrated Circuit Card): A card or tag using the ISO 14443A 
 * interface, eg Mifare or NTAG203.
 */

#include <SPI.h>
#include <MFRC522.h>
 
#define SS_PIN 10
#define RST_PIN 9
#define CTRL_FLAGS 16

MFRC522::MIFARE_Key key;
MFRC522 mfrc522(SS_PIN, RST_PIN);   // Create MFRC522 instance.
MFRC522::StatusCode status;

// Global flags to set note lang is
// set in writeFlagsBlockData for 
// demonstration purposes.
byte firstFlagSet = B00000001; //first control block. Set to split mode
byte secondFlagSet = B00000000; //Not in use currently
byte majorVersion = B00000001; // Version 1
byte minorVersion = B00000000; // no minor number
byte debug = B00000000; //not in debug mode can be all ones or all zeros currently

 
void setup() 
{
  Serial.begin(9600);   // Initiate a serial communication
  SPI.begin();      // Initiate  SPI bus
  mfrc522.PCD_Init();   // Initiate MFRC522
  Serial.println("Write RFAV data to to MIFARE PICC");
}

void loop() 
{
  
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }

  Serial.print(F("Card UID:"));    //Dump UID
  for (byte i = 0; i < mfrc522.uid.size; i++) {
    Serial.print(mfrc522.uid.uidByte[i] < 0x10 ? " 0" : " ");
    Serial.print(mfrc522.uid.uidByte[i], HEX);
  }
  
  Serial.print(F(" PICC type: "));   // Dump PICC type
  MFRC522::PICC_Type piccType = mfrc522.PICC_GetType(mfrc522.uid.sak);
  Serial.println(mfrc522.PICC_GetTypeName(piccType));

  Serial.setTimeout(20000L) ;     // wait until 20 seconds for input from serial
  // Ask Flag control data block 
  writeFlagsBlockData();
  //mfrc522.PICC_HaltA(); // Halt PICC
} 

/**
 * Here we write our input data to the first four bytes of 
 * block 1. Uses global vars declared at top of program.  
 * FLags inline with RFAV version 1 can be set in the four 
 * binary variables: firstFlagSet, secondFlagSet, majorVersion,
 * minorVersion.
 * The debug mode is currently 000000000 for false and
 * 11111111 for true. It occupies one byte.
 * Three bytes are used to represent language in accordance with 
 * ISO 639-2. 
 * 
 */
void writeFlagsBlockData() {
  // Write block
  byte flagBuffer[16];
  byte block;


  //Uses global vars 
  flagBuffer[0] = firstFlagSet;
  flagBuffer[1] = secondFlagSet;
  flagBuffer[2] = majorVersion;
  flagBuffer[3] = minorVersion;
  flagBuffer[7] = debug;

  /** 
   *  Demonstration of how we can set
   * the language using ISO 639-2
   * to English 
   * 
   */
  flagBuffer[4] = char('e');
  flagBuffer[5] = char('n');
  flagBuffer[6] = char('g');
  
  
  block = 1;

  for(int i=7; i < 16; i++ ){
    flagBuffer[i] = 0;
  }

  //Serial.println(F("Authenticating using key A..."));
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }
  else Serial.println(F("PCD_Authenticate() success: "));

  
  status = mfrc522.MIFARE_Write(block, flagBuffer, 16);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else {
    Serial.println(F("MIFARE_Write() success: "));
  }
  writeUserData();
  mfrc522.PICC_DumpToSerial(&(mfrc522.uid));
}

/**
 * Now check whether we are in split
 * mode or not. Split mode
 * divides the User data into two 
 * logical segements:
 * 1. The AR label displayed
 * 2. A URL displayed that can be clicked
 * on launch a browser. 
 */
void writeUserData() {
  if(bitRead(firstFlagSet, 0) == 1) {
    useSplitMode();
  } else {
    writeTagLabel();
  }
}

/**
 * If the RFID tag is in split mode, the User data 
 * is split 50/50 between storing a label and
 * between storing a URL. 
 * For demonstration purposes we do not split
 * the whole User data 50 but simply write to
 * blocks 2 and 4 for label data and 5 and 6 for 
 * URL data. 
 */
void useSplitMode() {
  Serial.println("In split mode");
  writeTagLabel();
  writeTagURL();
}

/**
 * Grab user input from Serial and write to blocks
 * 2 and 4 avoiding the reserved block of 3.
 */
void writeTagLabel() {

  byte labelBuffer[34];
  byte block;
  byte len;

  Serial.println(F("Enter label data #"));
  len = Serial.readBytesUntil('#', (char *) labelBuffer, 30) ; // read family name from serial
  
  for (byte i = len; i < 30; i++) {
    labelBuffer[i] = ' '; // pad with spaces
  }

  block = 2;
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
 
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else { 
    Serial.println(F("PCD_Authenticate() success: "));
  }

  // Write block
  status = mfrc522.MIFARE_Write(block, labelBuffer, 16);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else {
    Serial.println(F("MIFARE_Write() success: "));
  }

  block = 4; //skip block 3 on the MIFARE as this is reserved.
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Write block
  status = mfrc522.MIFARE_Write(block, &labelBuffer[16], 16);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else { 
    Serial.println(F("MIFARE_Write() success: "));
  }
}

/**
 * Grab user input from Serial and write to blocks
 * 5 and 6.
 */
void writeTagURL() {

  byte urlBuffer[34];
  byte block;
  byte len;

  Serial.println(F("Enter URL #"));
  len = Serial.readBytesUntil('#', (char *) urlBuffer, 30) ; // read family name from serial
  
  for (byte i = len; i < 30; i++) {
    urlBuffer[i] = ' '; // pad with spaces
  }

  block = 5;
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
 
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else { 
    Serial.println(F("PCD_Authenticate() success: "));
  }

  // Write block
  status = mfrc522.MIFARE_Write(block, urlBuffer, 16);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else {
    Serial.println(F("MIFARE_Write() success: "));
  }

  block = 6; 
  status = mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid));
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("PCD_Authenticate() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  }

  // Write block
  status = mfrc522.MIFARE_Write(block, &urlBuffer[16], 16);
  
  if (status != MFRC522::STATUS_OK) {
    Serial.print(F("MIFARE_Write() failed: "));
    Serial.println(mfrc522.GetStatusCodeName(status));
    return;
  } else { 
    Serial.println(F("MIFARE_Write() success: "));
  }
  
} 
  


