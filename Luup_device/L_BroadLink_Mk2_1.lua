-- a-lurker, copyright, 10 December 2017

-- Tested on a Vera 3

--[[
    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    version 3 (GPLv3) as published by the Free Software Foundation;

    In addition to the GPLv3 License, this software is only for private
    or home usage. Commercial utilisation is not authorized.

    The above copyright notice and this permission notice shall be included
    in all copies or substantial portions of the Software.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
]]
--[[
    On purchase the BroadLink device is in a mode where it can be configured via a mobile phone.
    We need to change the mode to AP mode. Place the BroadLink device into AP mode by holding
    down the reset button about four seconds. A successful change to AP mode is indicated by the
    blue LED: four slow flashes followed by a one second pause.

    At this point the device acts as WiFi access point (AP). It runs a DCHP server on 192.168.10.1
    Any Vera, PC, etc, that connects to the AP, will be given an address of 192.168.10.2, which will
    increment, as further devices are connected to the AP.

    We need to send a pairing message to the AP on 92.168.10.1 In this pairing message, we
    send the WiFi SSID and password of the AP that is part of our Vera network. Once successfully
    received, the BroadLink device with disable its own AP and DCHP server and connect to the AP
    specified in our message ie the LAN connected to Vera. The blue LED goes completely off.
    The BroadLink device effectively stops acting as an AP and changes to being a slave device.
    At this point we can start to use the facilities the BroadLink device offers.
    Refer to: sendPairingMsg(), which works but is not called by this code.

    Devices use broadcast and multicast on 224.0.0.251

    Refs:
       https://github.com/mjg59/python-broadlink
       https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1
       https://github.com/sayzard/BroadLinkESP/blob/master/BroadLinkESP.cpp
]]

local PLUGIN_NAME      = 'BroadLink_Mk2'
local PLUGIN_SID       = 'urn:a-lurker-com:serviceId:'..PLUGIN_NAME..'_1'
local PLUGIN_VERSION   = '0.51'
local THIS_LUL_DEVICE  = nil

-- your WiFi SSID and PASS. Only required if not using the phone
-- app to pair the BroadLink device. Refer to: sendPairingMsg()
local SSID             = 'my_SID'
local PASS             = 'my_PASS'

local DEV = {
    BINARY_LIGHT       = 'urn:schemas-upnp-org:device:BinaryLight:1',                -- also energy metering
    DOOR_SENSOR        = 'urn:schemas-micasaverde-com:device:DoorSensor:1',          -- security sensor
    GENERIC_SENSOR     = 'urn:schemas-micasaverde-com:device:GenericSensor:1',
    HUMIDITY_SENSOR    = 'urn:schemas-micasaverde-com:device:HumiditySensor:1',
    IR_TRANSMITTER     = 'urn:schemas-micasaverde-com:device:IrTransmitter:1',
    LIGHT_SENSOR       = 'urn:schemas-micasaverde-com:device:LightSensor:1',
    MOTION_SENSOR      = 'urn:schemas-micasaverde-com:device:MotionSensor:1',        -- security sensor
    SMOKE_SENSOR       = 'urn:schemas-micasaverde-com:device:SmokeSensor:1',         -- security sensor
    TEMPERATURE_SENSOR = 'urn:schemas-micasaverde-com:device:TemperatureSensor:1'
}

local FILE = {
    BINARY_LIGHT       = 'D_BinaryLight1.xml',
    DOOR_SENSOR        = 'D_DoorSensor1.xml',
    GENERIC_SENSOR     = 'D_GenericSensor1.xml',
    HUMIDITY_SENSOR    = 'D_HumiditySensor1.xml',
    IR_TRANSMITTER     = 'D_BroadLink_Mk2_IrRf_1.xml',    -- overrides:  'D_IrTransmitter1.xml'
    LIGHT_SENSOR       = 'D_LightSensor1.xml',
    MOTION_SENSOR      = 'D_MotionSensor1.xml',
    SMOKE_SENSOR       = 'D_SmokeSensor1.xml',
    TEMPERATURE_SENSOR = 'D_TemperatureSensor1.xml'
}

local SID = {
    BINARY_LIGHT       = 'urn:upnp-org:serviceId:SwitchPower1',
    DOOR_SENSOR        = 'urn:micasaverde-com:serviceId:SecuritySensor1',
    ENERGY_METERING    = 'urn:micasaverde-com:serviceId:EnergyMetering1',   -- see FILE.BINARY_LIGHT
    GENERIC_SENSOR     = 'urn:micasaverde-com:serviceId:GenericSensor1',
    HA                 = 'urn:micasaverde-com:serviceId:HaDevice1',
    HUMIDITY_SENSOR    = 'urn:micasaverde-com:serviceId:HumiditySensor1',
    IR_TRANSMITTER     = 'urn:a-lurker-com:serviceId:IrTransmitter1',       -- 'urn:micasaverde-com:serviceId:IrTransmitter1'
    LIGHT_SENSOR       = 'urn:micasaverde-com:serviceId:LightSensor1',
    MOTION_SENSOR      = 'urn:micasaverde-com:serviceId:SecuritySensor1',
    SMOKE_SENSOR       = 'urn:micasaverde-com:serviceId:SecuritySensor1',
    TEMPERATURE_SENSOR = 'urn:upnp-org:serviceId:TemperatureSensor1'
}

local BROADLINK_AP_IP  = '192.168.10.1'
local UDP_IP_PORT      = 80
local OUR_IP           = ''
local MSG_TIMEOUT      = 1

local FIVE_MIN_IN_SECS = 300
local m_PollInterval   = FIVE_MIN_IN_SECS
local m_PollEnable     = ''  -- is set to either: '0' or '1'
local m_msgCount       = -1
local m_doEncodeDecode = true  -- used for testing purposes only

-- AES-128 CBC algorithm with no padding
local initialKey    = '097628343fe99e23765c1513accf8b02' -- 0x09, 0x76, 0x28, 0x34, 0x3f, 0xe9, 0x9e, 0x23, 0x76, 0x5c, 0x15, 0x13, 0xac, 0xcf, 0x8b, 0x02
-- Note: IVs should not be reused!
local initialVector = '562e17996d093d28ddb3ba695a2e6f58' -- 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58

-- SO WHAT'S WITH ALL THE PLUS ONES???? - it was easier to follow the reference information that way - that's why!
-- So most hex numbers shown start with a C style zero base and have one added on produce a one as the starting point for Lua.
-- It's also nice to use Lua's ipairs and for 'length = #table' to give the correct answer!

-- checksum bytes
local idxChkSum        = {msb = 0x21+1, lsb = 0x20+1}
-- error msg bytes
local idxError         = {msb = 0x23+1, lsb = 0x22+1}
-- device id bytes
local idxDeviceId      = {msb = 0x25+1, lsb = 0x24+1}
-- msg count bytes
local idxCount         = {msb = 0x29+1, lsb = 0x28+1}   -- used to match incoming responses to outgoing messages
-- payload checksum bytes
local idxPayloadChkSum = {msb = 0x35+1, lsb = 0x34+1}

-- command and response codes
local blCmds = {
    discoverAPs     = {tx = 0x1a, rx = 0x1b},
    pairing         = {tx = 0x14, rx = 0x15},
    discoverDevices = {tx = 0x06, rx = 0x07},
    auth            = {tx = 0x65, rx = 0xe9},   -- 0x3e9, we'll ignore the msb
    sp1             = {tx = 0x66, rx = 0xe9},   -- no idea if 0x3e9 is returned or not???? HACK
    readWrite       = {tx = 0x6a, rx = 0xee}    -- 0x3ee, we'll ignore the msb
}

-- payload commands are placed at the 1st byte (0x00) of the payload (well - seem to be)
local plCmds = {
    off          = 0x01,   -- cmd = 0x6a, 4 byte payload
    on           = 0x02,   -- cmd = 0x6a, 4 byte payload
    get          = 0x01,   -- cmd = 0x6a, 16 byte payload
    set          = 0x02,   -- cmd = 0x6a, 4 byte + payload size ie off, on, ir/rf data: location 0x05 = 0x26 for ir data, else rf data
    irLearnStart = 0x03,   -- cmd = 0x6a, 16 byte payload
    irGetCode    = 0x04,   -- cmd = 0x6a, 16 byte payload
    mp1StripPwr  = 0x0a,   -- cmd = 0x6a, 16 byte payload
    mp1StripSw   = 0x0d,   -- cmd = 0x6a, 16 byte payload
    rfLearnStart = 0x19,   -- cmd = 0x6a, 16 byte payload
    rfGetCode1   = 0x1a,   -- cmd = 0x6a, 16 byte payload
    rfGetCode2   = 0x1b,   -- cmd = 0x6a, 16 byte payload
    rfLearnStop  = 0x1e    -- cmd = 0x6a, 16 byte payload
}

-- payload data starts at the 5th byte (0x05) of the payload
local plData = {
    off = 0x00,
    on  = 0x01,
    ir  = 0x26   -- IR sequences start with this flag being set to 0x26. RF sequences do not.
}

-- payload sensors
local plData = {
    temperature = {msb = 0x04+1, lsb = 0x05+1},
    humidity    = {msb = 0x06+1, lsb = 0x07+1},
    lightLevel  =  0x08+1,
    airQuality  =  0x0a+1,
    noiseLevel  =  0x0c+1
}

local blDevs = {}

--[[
blDevices[blId] = {   blId: the id of a BroadLink physical device: we'll use the BroadLink device's mac address

    -- the following derived from discovery broadcast process
    blIp           = ipInMsg,                    ip address of  the host BroadLink device
    blMac          = mac,                        mac address of the host BroadLink device
    blDevLookup    = blDevLookup,                id of the host BroadLink device 'type'
    blDesc         = blDevs[blDevLookup].desc,   description of the host BroadLink device eg "RM pro", etc

    -- thefollowing derived from authorisation process
    blInternalId   = internalId,                 the id  returned from the BroadLink host device during the authorisation process
    blKey          = key,                        the key returned from the BroadLink host device during the authorisation process
}
]]

local blDevices = {}

--[[
All the Vera devices eg: temperature sensors, relays, etc and in which physical BroadLink device they are located

veraDevices[altId] = {   altId, as used by the this vera plugin, of the form: host mac address plus the vera function type
    blId           = blId                        the id of the BroadLink parent device - which is simply its mac address
    veraDesc       = veraDesc,                   vera device description, as seen in the user interface
    veraDevice     = dev,                        vera device type - for child creation
    veraFile       = file                        vera device file - for child creation
    veraFunc       = func                        vera device function
}
]]

local veraDevices = {}

-- http://w3.impa.br/~diego/software/luasocket/reference.html
local socket = require('socket')

-- don't change this, it won't do anything. Use the debugEnabled flag instead
local DEBUG_MODE = true

local function debug(textParm, logLevel)
    if DEBUG_MODE then
        local text = ''
        local theType = type(textParm)
        if (theType == 'string') then
            text = textParm
        else
            text = 'type = '..theType..', value = '..tostring(textParm)
        end
        luup.log(PLUGIN_NAME..' debug: '..text,50)

    elseif (logLevel) then
        local text = ''
        if (type(textParm) == 'string') then text = textParm end
        luup.log(PLUGIN_NAME..' debug: '..text, logLevel)
    end
end

-- If non existent, create the variable
-- Update the variable only if needs to be
local function updateVariable(varK, varV, sid, id)
    if (sid == nil) then sid = PLUGIN_SID      end
    if (id  == nil) then  id = THIS_LUL_DEVICE end

    if ((varK == nil) or (varV == nil)) then
        luup.log(PLUGIN_NAME..' debug: '..'Error: updateVariable was supplied with a nil value', 1)
        return
    end

    local newValue = tostring(varV)
    --debug(varK..' = '..newValue)
    debug(newValue..' --> '..varK)

    local currentValue = luup.variable_get(sid, varK, id)
    if ((currentValue ~= newValue) or (currentValue == nil)) then
        luup.variable_set(sid, varK, newValue, id)
    end
end

-- Iterator that returns the IDs of all the vera devices distributed amongst the BroadLink physical devices
local function broadLinkBasedVeraDevices()
    local devicesList = {}

    for deviceID, v in pairs(luup.devices) do
        if (v.device_num_parent == THIS_LUL_DEVICE) then
            table.insert(devicesList, deviceID)
        end
    end

    local i = 0
    local iter = function ()
        i = i + 1
        if devicesList[i] == nil then return nil
        else return devicesList[i] end
    end

    return iter
end

-- Compute the difference in seconds between local time and UTC including daylight saving
local function get_timezone_offset()
    local ts        = os.time()
    local utcdate   = os.date('!*t', ts)
    local localdate = os.date('*t', ts)
    localdate.isdst = false -- this is the trick
    return os.difftime(os.time(localdate), os.time(utcdate)), localdate
end

-- Split a word over two bytes and insert it as specified
local function insertMsbLsb(msgTab, location, var)
    local msb = math.floor(var/0x100)
    msgTab[location.lsb] = var - (msb * 0x100)
    msgTab[location.msb] = msb
end

-- The whole message is checksumed. This is done after everything else, including encryption
local function insertChecksum(msgTab)
    local checksum = 0xbeaf    -- checksum seed
    for i = 1, #msgTab do
        checksum = checksum + msgTab[i]
        if (checksum >= 0x10000) then checksum = checksum - 0x10000 end
    end
    insertMsbLsb(msgTab, idxChkSum, checksum)
end

-- Overall checksum ok?
local function validChecksum(rxMsgTab)
    -- get the checksum in the returned message
    local msgCheckum = rxMsgTab[idxChkSum.msb]*256 + rxMsgTab[idxChkSum.lsb]

    -- zero it out before rechecking
    rxMsgTab[idxChkSum.msb], rxMsgTab[idxChkSum.lsb] = 0x00, 0x00

    local checksum = 0xbeaf    -- checksum seed
    for i = 1, #rxMsgTab do
        checksum = checksum + rxMsgTab[i]
        if (checksum >= 0x10000) then checksum = checksum - 0x10000 end
    end
    return msgCheckum == checksum
end

-- Payloads have their own checksum, which is calculated and inserted in the header before the payload is encryted
local function insertPayloadChecksum(headerTab, payloadTab)
    local checksum = 0xbeaf    -- checksum seed
    for i = 1, #payloadTab do
        checksum = checksum + payloadTab[i]
        if (checksum >= 0x10000) then checksum = checksum - 0x10000 end
    end
    insertMsbLsb(headerTab, idxPayloadChkSum, checksum)
end

-- Payload checksum ok?
local function validPayloadChecksum(rxMsgTab, payloadTab)
    -- get the checksum in the returned message
    local payloadCheckum = rxMsgTab[idxPayloadChkSum.msb]*256 + rxMsgTab[idxPayloadChkSum.lsb]

    local checksum = 0xbeaf    -- checksum seed
    for i = 1, #payloadTab do
        checksum = checksum + payloadTab[i]
        if (checksum >= 0x10000) then checksum = checksum - 0x10000 end
    end
    return payloadCheckum == checksum
end

-- Responses to tx'ed messages return this count, so the replies to tx'ed messages can be matched together
local function insertMsgCount(msgTab)
    m_msgCount = m_msgCount+1

    -- Warning: if m_msgCount >= 0x7ffe at this point then things stop working eg IR stops transmitting.
    -- Presumably this is due to numbers in the host device wrapping around to negative values.
    -- We'll just limit the count range from 0 to 4095 to keep it simple
    if (m_msgCount >= 0x1000) then m_msgCount = 0 end
    insertMsbLsb(msgTab, idxCount, m_msgCount)
end

-- Table creation for messages
local function makeEmptyTable(length)
    local nullTab = {}
    -- set the table to all nulls
    for i = 1, length do nullTab[i] = 0x00 end
    return nullTab
end

-- Magically gets our vera's local ip address
local function getOurIPaddress()
    local SOME_RANDOM_IP   = '1.1.1.1'
    local SOME_RANDOM_PORT = '1'

    local udp = socket.udp()
    if (udp == nil) then debug('Socket failure: socket lib missing?',50) return '' end
    udp:setpeername(SOME_RANDOM_IP, SOME_RANDOM_PORT)

    -- now we can get our LAN IP address
    local ipa,_,_ = udp:getsockname()
    udp:close()

    return ipa
end

-- AES encryption requires the message to be multiples of 16 bytes ie 128 bits. Pad with zeroes as needed.
local function padForAES(padThisTable)
    local remainder = #padThisTable % 16  -- 0 to 15
    if (remainder ~= 0) then for i = 15, remainder, -1 do table.insert(padThisTable, 0x00) end end
end

-- Do the AES encrypt or decrypt on the payload only.
-- If the input is a string then the output is a string.
-- If the input is a table of bytes then the output is a table of bytes.
local function encryptDecrypt(key, input, encrypt)
    if ((not key) or (key:len() ~= 32)) then debug ('AES key missing or incorrect size') return nil end

    local inputStr = input
    if (type(input) == 'table') then
        local strTab = {}
        -- table.concat does coercion of numbers which we don't want
        -- effectively here, we are setting all the elements to type char
        for i=1, #input do table.insert(strTab, string.char(input[i])) end
        inputStr = table.concat(strTab)
    end

    debug ('AES inputStr length = '..tostring(inputStr:len()))
    if (DEBUG_MODE and encrypt) then
        local inputHexTab = {}
        for c in inputStr:gmatch('.') do table.insert(inputHexTab, string.format('%02x', c:byte())) end
        debug(table.concat(inputHexTab, ' '))
    end

    -- Tried using echo to pipe into openssl but got into too much
    -- trouble with escaping. So we'll use a file as input instead.
    local inputFile = io.open('/tmp/BroadLink.in', 'wb+')
    if (inputFile) then
        inputFile:write(inputStr)
        inputFile:close()
    end

    -- encrypting or decrypting?
    local inOut = '-d'
    if (encrypt) then inOut = '-e' end

    -- https://www.openssl.org/docs/manmaster/man1/enc.html
    local encDecCmdTab = {
    'openssl',
    'enc',                    -- use a symmetric cipher
    '-aes-128-cbc',           -- Cipher Block Chaining (CBC) mode for AES assumes data in blocks of 16 bytes
    inOut,                    -- encrypt/decrypt
    '-nopad',                 -- we will do the padding. Default uses https://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7
    '-in /tmp/BroadLink.in',  -- don't use an output file; we'll capture the stdout data instead
    '-K',
    key,                      -- string of hex digits
    '-iv',
    initialVector             -- string of hex digits
    }
    local encDecCmd = table.concat(encDecCmdTab,' ')
    debug (encDecCmd)

    -- capture the stdout data
    local pipeOut   = assert(io.popen(encDecCmd, 'r'))
    local outputStr = assert(pipeOut:read('*a'))
    pipeOut:close()

    debug ('AES outputStr length = '..tostring(outputStr:len()))
    if (DEBUG_MODE and not encrypt) then
        local outputHexTab = {}
        for c in outputStr:gmatch('.') do table.insert(outputHexTab, string.format('%02x', c:byte())) end
        debug(table.concat(outputHexTab, ' '))
    end

    if (type(input) == 'string') then return outputStr end

    local outputTab = {}
    for c in outputStr:gmatch('.') do
        table.insert(outputTab, string.byte(c))
    end

    return outputTab
end

-- for testing only
local function testAES()
    local inputTab = {0x5c, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x00, 0xff, 0x00, 0x00}
    local encodeDecode = encryptDecrypt(initialKey, inputTab, true)
    local outputStr = encryptDecrypt(initialKey, encodeDecode, false)
end

-- Convert a Pronto IR code to a Broadlink IR code
-- accepts a string in
-- returns a byte table
local function prontoCode2blCode(pCode)
--[[
    Pronto IR format:
    http://www.majority.nl/files/prontoirformats.pdf
    http://www.remotecentral.com/features/irdisp2.htm
    http://forum.micasaverde.com/index.php/topic,37268.msg321338.html#msg321338

    BroadLink IR format:
    https://github.com/mjg59/python-broadlink/issues/57
    BLCode[0x00] = 0x26 = IR, 0xd7 for RF 315MHz, 0xb2 for RF 433MHz
    BLCode[0x01] = repeat count, 0x0 no repeat, 0x1 repeat twice, etc
    BLCode[0x02] = lsb length of the following data including the terminator in bytes
    BLCode[0x03] = msb length of the following data including the terminator in bytes
    BLCode[0x04] = length of the mark or the space, starting with a mark, in 32836.9140625 Hz periods
    BLCode[last] = 0x0d 0x05 at the end for IR only (terminator)
    Notes:
       the lengths are a single byte, if < 256, else they are 3 bytes as:  '0x00, msb, lsb'
       the hex codes can be upper or lower case
]]
    local ir = {
        method       = 0x01,
        freqDiv      = 0x02,
        onceSeqCnt   = 0x03,
        repeatSeqCnt = 0x04,
        burstStart   = 0x05
    }

    local pCodeTab = {}
    for pc in pCode:gmatch('%x+') do table.insert(pCodeTab, tonumber(pc,16)) end

    -- we'll only do "raw" Prontos with no "once" sequence
    if ((pCodeTab[ir.method] ~= 0) and (pCodeTab[ir.onceSeqCnt] ~= 0)) then
        debug('Only raw Pronto Codes with no "once" sequence allowed',50)
        return {}
    end

    local PRONTO_PWM_HZ = 4145152  -- a constant measured in Hz and is the pulse width modulator frequency used by the Philip's Pronto remotes

    -- blFreqHz:  possibly a watch xtal frequency at 32,768 Hz ????
    local pcFreqHz     = PRONTO_PWM_HZ / pCodeTab[ir.freqDiv]
    local blFreqHz     = 32836.9140625   -- =(269/8192)*1e6   and (268/8192)*1e6=32714.84375
    local freqRatio    = blFreqHz/pcFreqHz
    local burstPairCnt = pCodeTab[ir.repeatSeqCnt]

    local irCodeTab = {
        0x26,   -- IR code flag, not 315/433 MHz RF
        0x00,   -- no repeats
        0x00,   -- lsb byte count excluding lead in (little endian)
        0x00    -- msb byte count excluding lead in
    }

    local byteCnt = 0
    for i = ir.burstStart, #pCodeTab do
        local numPeriods = math.floor((pCodeTab[i] * freqRatio) + 0.5)
        if (numPeriods > 256) then
            local msb = math.floor(numPeriods / 0x100)
            local lsb = numPeriods - (msb * 0x100)
            table.insert(irCodeTab, 0x00)  -- dual byte starting flag
            table.insert(irCodeTab, msb)   -- big endian
            table.insert(irCodeTab, lsb)   -- big endian
            byteCnt = byteCnt+3
        else
            table.insert(irCodeTab, numPeriods)
            byteCnt = byteCnt+1
        end
    end
     -- append the lead out
    table.insert(irCodeTab, 0x0d)
    table.insert(irCodeTab, 0x05)
    byteCnt = byteCnt+2   -- the lead out is included in the count

    local msbBC = math.floor(byteCnt / 0x100)
    local lsbBC = byteCnt - (msbBC * 0x100)

    irCodeTab[0x03] = lsbBC   -- little endian
    irCodeTab[0x04] = msbBC   -- little endian

    -- for debugging purposes only
    if (DEBUG_MODE) then
        local irCodeTabHex = {}
        for _,v in ipairs(irCodeTab) do
            table.insert(irCodeTabHex, string.format('%02x', v))
        end
        debug('Broadlink IR code 1 = '..table.concat(irCodeTabHex,' '))
    end

    return irCodeTab
end

-- Add each physical BroadLink device to the list of BroadLink devices
local function addToBroadlinkPhysicalDevicesList(rxMsg, ip)
--[[
    The response contains the 48 bytes we sent above, with updated checksum,
    plus another 80 bytes of info, making a total of 128 bytes.

    0x26+1 = 0x7 reply to "discoverDevices" request blCmds.discoverDevices.rx
    0x35+1 to 0x34+1 = device type eg as 2 bytes indicating "RM2 Pro Plus 2" etc. This determines capabilities.
    0x39+1 to 0x36+1 = ip  address
    0x3f+1 to 0x3a+1 = MAC address
    0x40+1 to 0x4b+1 = a string of varying length in UTF8 For example: e699bae883bde981a5e68ea7 = Chinese for “intelligent remote control”
    plus other unknown stuff
]]
    -- ignore local loopback
    if (ip == OUR_IP) then return end

    -- convert the rx'ed string to a table of bytes
    local rxMsgTab = {}
    for c in rxMsg:gmatch('.') do table.insert(rxMsgTab, string.byte(c)) end
    local rxMsgLen = #rxMsgTab

    debug('Rx\'ed a discovery response: rxMsg length = '..tostring(rxMsgLen))
    for i = 1, rxMsgLen do debug(string.format('%3d %02x', rxMsgTab[i], rxMsgTab[i])) end

    -- sanity checks
    if (rxMsgLen ~= 128) then debug('Error: discovery msg - incorrect size',50) return end
    if (rxMsgTab[0x26+1] ~= blCmds.discoverDevices.rx) then return end

    -- get the ip address contained in the returned message
    local strTab = {}
    for i = 0x39+1, 0x36+1, -1 do table.insert(strTab, tostring(rxMsgTab[i],10)) end
    local ipInMsg = table.concat(strTab,'.')

    -- get the mac address
    strTab = {}
    for i = 0x3f+1, 0x3a+1, -1 do table.insert(strTab, string.format('%02x',rxMsgTab[i])) end

    -- get the mac address and use it as part of a BroadLink device blId and the Vera device altId
    -- indices are case sensitive, so force to lower just in case
    local mac = string.lower(table.concat(strTab,':'))
    local blId = mac

    -- get the hex number that represents this particular BroadLink device
    local blDevLookup = rxMsgTab[0x35+1]*256 + rxMsgTab[0x34+1]

    blDevices[blId] = {
        blIp         = ipInMsg,
        blMac        = mac,
        blDevLookup  = blDevLookup,
        blDesc       = blDevs[blDevLookup].desc,

        -- the following will be filled in during the authorisation process
        blInternalId = '????',
        blKey        = initialKey
    }

    debug(blId)
    debug(blDevices[blId].blIp)
    debug(blDevices[blId].blMac)   -- same as blId
    debug(string.format('0x%04x', blDevices[blId].blDevLookup))
    debug(blDevices[blId].blDesc)
    debug(blDevices[blId].blInternalId)
    debug(blDevices[blId].blKey)

    local BLink = blDevices[blId].blDesc..' - '
    local altId, veraDesc, dev, file = '', '', DEV.BINARY_LIGHT, FILE.BINARY_LIGHT

    for k, v in pairs(blDevs[blDevLookup].devs) do
        altId = mac..'_'..k
        debug('k = '..k)
        -- get the function for this vera device
        func = v

        if (k=='rly1') then
            veraDesc = BLink..'relay 1'
        elseif (k=='rly2') then
            veraDesc = BLink..'relay 2'
        elseif (k=='rly3') then
            veraDesc = BLink..'relay 3'
        elseif (k=='rly4') then
            veraDesc = BLink..'relay 4'
        elseif (k=='humidity') then
            veraDesc = BLink..'humidity 1'
            dev, file = DEV.HUMIDITY_SENSOR, FILE.HUMIDITY_SENSOR
        elseif (k=='ir') then
            veraDesc = BLink..'IR 1'
            dev, file = DEV.IR_TRANSMITTER, FILE.IR_TRANSMITTER
        elseif (k=='lightLevel') then
            veraDesc = BLink..'light level 1'
            dev, file = DEV.LIGHT_SENSOR, FILE.LIGHT_SENSOR
        elseif (k=='noise') then
            veraDesc = BLink..'noise level 1'
            dev, file = DEV.GENERIC_SENSOR, FILE.GENERIC_SENSOR
--        elseif (k=='rf315') then
--            veraDesc = BLink..'RF 315 1'
--            dev, file = DEV.IR_TRANSMITTER, FILE.IR_TRANSMITTER
--        elseif (k=='rf433') then
--            veraDesc = BLink..'RF 433 1'
--            dev, file = DEV.IR_TRANSMITTER, FILE.IR_TRANSMITTER
        elseif (k=='temp') then
            veraDesc = BLink..'temperature 1'
            dev, file = DEV.TEMPERATURE_SENSOR, FILE.TEMPERATURE_SENSOR
        elseif (k=='voc') then
            veraDesc = BLink..'light level 1'
            dev, file = DEV.GENERIC_SENSOR, FILE.GENERIC_SENSOR
        else
            altId = nil
            debug('k = '..k..' has no associated code at this time')
        end

        if (altId) then
            veraDevices[altId] = {
                blId         = blId,     -- same as mac address
                veraDesc     = veraDesc,
                veraDevice   = dev,
                veraFile     = file,
                veraFunc     = func
            }

            debug(altId)
            debug(veraDevices[altId].blId)
            debug(veraDevices[altId].veraDesc)
            debug(veraDevices[altId].veraDevice)
            debug(veraDevices[altId].veraFile)
            debug(veraDevices[altId].veraFunc)
        end
    end
end

-- Make the BroadLink "payload" header
local function makeCmdHeader(blId, payloadTab, command)
    -- length of the private header = 0x38 = 56dec
    local headerTab = makeEmptyTable(0x38)

    headerTab[0x00+1] = 0x5a   -- private header

    -- CID = 24113000182295205 = 00 55 aa a5 5a 55 aa a5 = 8 bytes
    headerTab[0x01+1] = 0xa5   -- lsb connection id
    headerTab[0x02+1] = 0xaa
    headerTab[0x03+1] = 0x55
    headerTab[0x04+1] = 0x5a
    headerTab[0x05+1] = 0xa5
    headerTab[0x06+1] = 0xaa
    headerTab[0x07+1] = 0x55   -- msb-1 connection id
  --headerTab[0x08+1] = 0x00   -- msb connection id (is already set to 0x00)

    -- insert the id of the host BroadLink device 'type' into the header: 0x25 to 0x24
    insertMsbLsb(headerTab, idxDeviceId, blDevices[blId].blDevLookup)

    headerTab[0x26+1] = command  -- command is typically 0x65, 0x66 or 0x6a

    -- insert the counter into the header: 0x29,0x28
    insertMsgCount(headerTab)

    -- the auth message gets the blInternalId, so when doing auth we skip this part
    local charIdx = 0x33+1
    if (command ~= blCmds.auth.tx) then
        for c in blDevices[blId].blInternalId:gmatch('%x%x') do
            headerTab[charIdx] = tonumber(c,16)
            charIdx = charIdx-1
        end
    end

    -- insert the mac address into the header: 0x2f to 0x2a
    charIdx = 0x2f+1
    for c in blDevices[blId].blMac:gmatch('%x%x') do
        headerTab[charIdx] = tonumber(c,16)
        charIdx = charIdx-1
    end

    -- the payload checksum is placed in the main header
    -- at 0x35, 0x34 before the payload is encrypted
    insertPayloadChecksum(headerTab, payloadTab)

    return headerTab
end

-- Combine the header and the payload
local function headerAndPayload(blId, payloadTab, command)
    -- only the payload is encrypted
    -- padding is added as needed, which is not that often; however
    -- the variable length IR messages certainly require it
    padForAES(payloadTab)

    -- we pass in the payloadTab, so its own checksum can be calculated and inserted into the main header
    local msgTab = makeCmdHeader(blId, payloadTab, command)

    -- use of m_doEncodeDecode is just for testing purpose
    local encodedTab = payloadTab
    if (m_doEncodeDecode) then encodedTab = encryptDecrypt(blDevices[blId].blKey, payloadTab, true) end

    -- append the AES encoded payload table to the header table
    for _,v in ipairs(encodedTab) do table.insert(msgTab, v) end

    -- always gets done last
    insertChecksum(msgTab)

    return msgTab
end

-- Make the BroadLink "discover APs" message
-- NOTE: could not get this to work! So code is not called.
local function makeDiscoverAPsMsg()
    -- 8 byte QUIC header + 40 byte payload = 48dec = 0x30
    local msgTab = makeEmptyTable(0x30)

    msgTab[0x26+1] = blCmds.discoverAPs.tx   -- "discoverAPs" request ID

    -- always gets done last
    insertChecksum(msgTab)

    return msgTab
end

-- The "pairing" message will be sent to the "BroadLinkProv" AP
-- Once sucessfully received, the BroadLink device deletes its
-- AP function and changes to a slave, connected to our LAN.
-- That's assuming the correct SSID and PASS were made use of.
-- The tx'ed msg carrys no payload
local function makePairingMsg()
    local securityType = 0x03   -- WPA2
    local ssidLen      = string.len(SSID)
    local passLen      = string.len(PASS)

    -- 8 byte QUIC header + 128 byte payload = 136 dec = 0x88
    local msgTab = makeEmptyTable(0x88)

    -- insert the SSID starting at 0x44 (68 dec), SSID can be up to 32 chars
    local charIdx = 0x44+1
    for c in SSID:gmatch('.') do
        msgTab[charIdx] = string.byte(c)
        charIdx = charIdx+1
    end

    -- insert the PASS starting at 0x64 (100 dec), PASS can be up to 32 chars
    charIdx = 0x64+1
    for c in PASS:gmatch('.') do
        msgTab[charIdx] = string.byte(c)
        charIdx = charIdx+1
    end

    msgTab[0x26+1] = blCmds.pairing.tx   -- "pairing" request ID
    msgTab[0x84+1] = ssidLen             -- insert msg length
    msgTab[0x85+1] = passLen             -- insert msg length
    msgTab[0x86+1] = securityType        -- request WPA2

    -- always gets done last
    insertChecksum(msgTab)

    return msgTab
end

-- Make the BroadLink "discover Devices" message
local function makeDiscoverDevicesMsg()
    local ipa1, ipa2, ipa3, ipa4 = OUR_IP:match('^(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)%.(%d%d?%d?)')

    -- note that JavaScript getTimezoneOffset returns the offset including dst in minutes
    -- note that get_timezone_offset is of the opposite sign to JavaScript getTimezoneOffset
    local tz, date = get_timezone_offset() -- seconds
    tz = -tz/3600  -- tz in hours with correct sign

    local tzMsb, tzIsb1, tzIsb2, tzLsb = 0, 0, 0, tz   -- in hours
    -- if tz is negative make a 32 bit negative integer
    if (tz < 0) then
        tzMsb, tzIsb1, tzIsb2 = 0xff, 0xff, 0xff
        tzLsb = (0xff + tz - 1) % 0xff
    end

    local port = UDP_IP_PORT
    local yearMsb = math.floor(date.year/256)
    local portMsb = math.floor(port/256)

    -- 8 byte QUIC header + 40 byte payload = 48dec = 0x30
    local msgTab = makeEmptyTable(0x30)

    msgTab[0x08+1] = tzLsb
    msgTab[0x09+1] = tzIsb2
    msgTab[0x0a+1] = tzIsb1
    msgTab[0x0b+1] = tzMsb   -- 32 bit int in hours
    msgTab[0x0c+1] = date.year - (yearMsb * 256)
    msgTab[0x0d+1] = yearMsb
    msgTab[0x0e+1] = date.sec
    msgTab[0x0f+1] = date.min
    msgTab[0x10+1] = date.hour
    msgTab[0x11+1] = date.day
    msgTab[0x12+1] = date.wday -1
    msgTab[0x13+1] = date.month
    msgTab[0x18+1] = ipa4
    msgTab[0x19+1] = ipa3
    msgTab[0x1a+1] = ipa2
    msgTab[0x1b+1] = ipa1
    msgTab[0x1c+1] = port - (portMsb * 256)
    msgTab[0x1d+1] = portMsb

    msgTab[0x26+1] = blCmds.discoverDevices.tx   --  "discover Devices" request ID

    -- always gets done last
    insertChecksum(msgTab)

    return msgTab
end

-- Make the BroadLink "auth" message
local function makeAuthorisationMsg(blId)
    -- length of the payload = 0x50 = 80dec
    local payloadTab = makeEmptyTable(0x50)

    -- note that blInternalId at payloadTab[0x00+1] to payloadTab[0x03+1] is (already) set to 0x00

    -- insert the key starting at 0x04+1, key is 2*16 chars long
    -- 097628343fe99e23765c1513accf8b02
    local charIdx = 0x04+1
    for c in blDevices[blId].blKey:gmatch('%x%x') do
        --debug(string.format('%02x',tonumber(c,16)))
        payloadTab[charIdx] = tonumber(c,16)
        charIdx = charIdx+1
    end

    payloadTab[0x2d+1] = 0x01  -- add in delimiter

--[[ apparently not required, but may be of use?
    -- insert friendly device name starting at 0x30 = 48dec
    myDevName = 'My device'
    charIdx = 0x30+1
    for c in myDevName:gmatch('.') do
        payloadTab[charIdx] = string.byte(c)
        charIdx = charIdx+1
    end
]]

    return headerAndPayload(blId, payloadTab, blCmds.auth.tx)
end

-- Make the BroadLink RMx "get temperature" message
local function makeRMGetTemperatureMsg(blId)
    -- length of the payload = 0x10 = 16dec
    local payloadTab = makeEmptyTable(0x10)

    -- we'll issue the get command
    payloadTab[0x00+1] = plCmds.get

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink SP1 "single relay off/on" message
local function makeSP1SetRelayMsg(blId, offOn)
    -- length of the payload = 0x04 = 4dec
    local payloadTab = makeEmptyTable(0x04)

    -- we'll issue the off/on command
    payloadTab[0x00+1] = plCmds.off
    payloadTab[0x01+1] = 0x04  -- is it correct that this should equal 0x04 ?
    payloadTab[0x02+1] = 0x04  -- is it correct that this should equal 0x04 ?
    payloadTab[0x03+1] = 0x04  -- is it correct that this should equal 0x04 ?

    -- on selected
    if (offOn) then payloadTab[0x00+1] = plCmds.on end

    return headerAndPayload(blId, payloadTab, blCmds.sp1.tx)
end

-- Make the BroadLink SP2 "single relay off/on" message
local function makeSP2SetRelayMsg(blId, offOn)
    -- length of the payload = 0x10 = 16dec
    local payloadTab = makeEmptyTable(0x10)

    -- we'll issue the off/on command
    payloadTab[0x00+1] = plCmds.set
    payloadTab[0x04+1] = plCmds.off

    -- on selected
    if (offOn) then payloadTab[0x04+1] = plCmds.on end

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink "IR & RF" message
local function makeRMTxIrRfMsg(blId, irRfCodeTab)
    -- UDP_MAX_PAYLOAD Warning: a host is not required to receive a datagram
    -- larger than 576 byte. So far not an issue with the BroadLink devices.

    -- length of the payload = 0x04 = 4dec + passed in data
    local payloadTab = makeEmptyTable(0x04)

    -- we'll issue the set command
    payloadTab[0x00+1] = plCmds.set

    if (irRfCodeTab) then
        -- append the IR/RF data table to the payload table
        for _,v in ipairs(irRfCodeTab) do table.insert(payloadTab, v) end
    else
        debug('Error: irRfCodeTab is nil',50)
    end

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink "relay off/on" message for a MP1 power strip
local function makeMP1RelayMsg(blId, offOn, relay)
    -- length of the payload = 0x10 = 16dec
    local payloadTab = makeEmptyTable(0x10)

    -- we'll issue the mp1Strip relay command
    payloadTab[0x00+1] = plCmds.mp1StripSw
    payloadTab[0x02+1] = 0xa5
    payloadTab[0x03+1] = 0xa5
    payloadTab[0x04+1] = 0x5a
    payloadTab[0x05+1] = 0x5a
    payloadTab[0x06+1] = 0xb2 + swMask   -- off
    payloadTab[0x07+1] = 0xc0
    payloadTab[0x08+1] = 0x02
    payloadTab[0x0a+1] = 0x03
    payloadTab[0x0d+1] = swMask
    payloadTab[0x0e+1] = 0x00   -- off

    -- shift the mask to the relay selected
    local swMask = 0x01
    for i = 2, relay -1 do swMask = swMask*2 end

    -- on selected
    if (offOn) then
        payloadTab[0x06+1] = 0xb2 + (swMask*2)
        payloadTab[0x0e+1] = swMask
    end

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink "read power" message for a MP1 power strip
local function makeMP1PowerMsg(blId)
    -- length of the payload = 0x10 = 16dec
    local payloadTab = makeEmptyTable(0x10)

    -- we'll issue the mp1Strip read power command
    payloadTab[0x00+1] = plCmds.mp1StripPwr
    payloadTab[0x02+1] = 0xa5
    payloadTab[0x03+1] = 0xa5
    payloadTab[0x04+1] = 0x5a
    payloadTab[0x05+1] = 0x5a
    payloadTab[0x06+1] = 0xae
    payloadTab[0x07+1] = 0xc0
    payloadTab[0x08+1] = 0x01

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Master send and receive with decrypted payload extraction
local function sendReceive(txMsgTab, ipAddress, key, msgType)
    local ok = false

    -- the send routine requires a string
    local strTab = {}
    -- table.concat does coercion of numbers, which we don't want.
    -- Here, we are effectively setting all the elements to char type
    -- as the send routine requires a string
    for i=1, #txMsgTab do table.insert(strTab, string.char(txMsgTab[i])) end
    local txMsg = table.concat(strTab)
    local txMsgLen = txMsg:len()

    -- sanity check: each table element should only be one byte
    if (txMsgLen ~= #txMsgTab) then debug('Error: not all the table elements are a single byte long',50) end

    local udp = socket.udp()
    udp:settimeout(MSG_TIMEOUT)

    debug(msgType..': txMsg length = '..txMsgLen..' Any payload is ENCODED')
    for c in txMsg:gmatch('.') do debug(string.format('%3d %02x', c:byte(), c:byte())) end

    -- Note: the maximum datagram size for UDP is (potentially) 576 bytes
    local resultTX, errorMsg = udp:sendto(txMsg, ipAddress, UDP_IP_PORT)

    if (resultTX == nil) then debug('TX of '..msgType..' msg to '..ipAddress..' failed: '..errorMsg) udp:close() return ok end

    -- Note: aircon codes can be very long. Buffer overruns of rx'ed messages will throw a checksum error.
    local rxMsg, ipOrErrorMsg = udp:receivefrom()
    udp:close()

    if (rxMsg == nil) then debug('RX of '..msgType..' msg response from '..ipAddress..' failed: '..ipOrErrorMsg) return ok end

    -- convert the rx'ed msg to a byte table - we like tables
    local rxMsgTab = {}
    for c in rxMsg:gmatch('.') do table.insert(rxMsgTab, string.byte(c)) end
    local rxMsgLen = #rxMsg

    -- have a look at the error information returned
    -- 0xfff9 means an error of some sort. The payload will be nil.
    local errorMsg = string.format('%02x%02x', rxMsgTab[0x23+1], rxMsgTab[0x22+1])
    if (errorMsg ~= '0000') then debug('Error: errorMsg = '..errorMsg,50) return ok end

    if (not validChecksum(rxMsgTab)) then debug('Error: rx\'ed msg checksum incorrect',50) return ok end

    -- get the received payload starting at 56h (zero based count as per the references)
    -- it may or may not be (ie "pairing msg response") encrypted
    local rxedPayloadTab = {}
    for i = 0x38+1, rxMsgLen do table.insert(rxedPayloadTab, rxMsgTab[i]) end
    if (#rxedPayloadTab == 0) then
        debug('No payload found')
        debug(msgType..': rxMsg length = '..tostring(rxMsgLen)..' UNdecoded msg follows:')
        for i = 1, rxMsgLen do debug(string.format('%3d %02x', rxMsgTab[i], rxMsgTab[i])) end
        return ok
    end

    -- decrypt the payload
    -- The "pairing" message doesn't encrypt/decrypt, so the key passed into this function will be
    -- nil on that occasion. Before authorisation is completed, the key will equal the "initialKey".
    -- After authorisation it will be key supplied by the discovery process.
    local payloadTab = {}
    if (m_doEncodeDecode and key) then
        payloadTab = encryptDecrypt(key, rxedPayloadTab, false)
    else  -- payload is not encrypted
        payloadTab = rxedPayloadTab
    end

    if ((#payloadTab > 0) and (not validPayloadChecksum(rxMsgTab, payloadTab))) then debug('Error: rx\'ed payload checksum incorrect',50) return ok end

    -- show the full received message complete with decoded payload
    debug(msgType..': rxMsg length = '..tostring(rxMsgLen)..' DECODED msg follows:')
    for i = 1, 0x37+1      do debug(string.format('%3d %02x', rxMsgTab[i],   rxMsgTab[i]))   end
    for i = 1, #payloadTab do debug(string.format('%3d %02x', payloadTab[i], payloadTab[i])) end

    ok = true
    return ok, payloadTab
end

--[[
    Send the "pairing" message to the "BroadLinkProv" AP
    returns true if the pairing was successful

    NOTE: for this to work your Vera or openLuup device must already be connected to
    the WiFi AP called "BroadlinkProv".

    Right from the start, you should be able to detect the AP with:   ping -c 10  192.168.10.2

    On an Arduino you need to append to this file:

        /etc/wpa_supplicant/wpa_supplicant.conf

    the following:

        # connect to a Broadlink provisioning AP
        network={
             ssid="BroadlinkProv"
             key_mgmt=NONE
        }

     A reboot of the Arduino is then required. sudo reboot or perhaps just reboot.
     iwinfo should indicate if the Arduino is connected to the AP before we do the pairing

     -- This code works but is not called. You need to provide your own SID and PASS.
]]
local function sendPairingMsg()
    -- Use the factory default BroadLink WiFi access point ip address.
    -- Note that the pairing msg contains no payload.
    -- Note the response contains no checksum
    local ok, payloadTab = sendReceive(makePairingMsg(), BROADLINK_AP_IP, nil, 'Pairing')
    return ok
end

-- Broadcast the "discover devices" message - as opposed to discovering APs msg
local function broadcastDiscoverDevicesMsg()
    local ok = false
    local udp = socket.udp()
    udp:settimeout(MSG_TIMEOUT)

    local txMsgTab = makeDiscoverDevicesMsg()
    -- HACK local txMsgTab = makeDiscoverAPsMsg()  -- can't get this to work! but it would be called like this, in this sort of framework.

    -- the send routine requires a string
    local strTab = {}
    -- table.concat does coercion of numbers, which we don't want.
    -- Here, we are effectively setting all the elements to char type
    for i=1, #txMsgTab do table.insert(strTab, string.char(txMsgTab[i])) end
    local txMsg = table.concat(strTab)

    local BROADCAST_IP = '255.255.255.255'
    -- HACK local MULTICAST_IP = '224.0.0.251'

    -- asterisk represents all the local interfaces on Vera eg Lan, WiFi, etc
    local setOK, failMsg = udp:setsockname('*', UDP_IP_PORT)
    if (setOK == nil) then
        debug('Set socket name failed: '..failMsg,50)
        udp:close()
        return ok
    end

    udp:setoption('broadcast', true)
    local resultTX, errorMsg = udp:sendto(txMsg, BROADCAST_IP, UDP_IP_PORT)
    -- HACK local resultTX, errorMsg = udp:sendto(txMsg, MULTICAST_IP, UDP_IP_PORT)
    if (resultTX == nil) then debug('Broadcast TX failed: '..errorMsg) udp:close() return ok end

    local rxMsg = nil
    local ipOrErrorMsg = ''
    -- repeat until the queue of all the device responses has been processed
    repeat
        -- allow for a msg length of 512. The receivefrom() function will block until timeout
        rxMsg, ipOrErrorMsg, _ = udp:receivefrom(512)
        if (rxMsg) then
            debug(ipOrErrorMsg)

            -- as the reponses to the broadcast are rx'ed, add the devices to the list
            addToBroadlinkPhysicalDevicesList(rxMsg, ipOrErrorMsg)
        end
    until (not rxMsg)

    udp:close()

    return ok
end

-- Send the "auth" message to the BroadLink device
-- returns true if the authorisation was successful
local function getAuthorisation(blId)
    local ok, payloadTab = sendReceive(makeAuthorisationMsg(blId), blDevices[blId].blIp, blDevices[blId].blKey, 'Authorisation')
    if (not ok) then return ok end

    -- extract the blInternalId from the response
    local strTab = {}
    for i = 3+1, 0+1, -1 do table.insert(strTab, string.format('%02x', payloadTab[i])) end
    blDevices[blId].blInternalId = table.concat(strTab)

    -- extract the key from the response
    strTab = {}
    for i = 4+1, 19+1 do table.insert(strTab, string.format('%02x', payloadTab[i])) end
    blDevices[blId].blKey = table.concat(strTab)

    debug('blKey and blInternalId: '..blDevices[blId].blKey..' '..blDevices[blId].blInternalId)

    return ok
end

-- Get the temperature from a BroadLink device
-- returns true if the get status was successful
local function getTemperature(blId)
    local ok, payloadTab = sendReceive(makeRMGetTemperatureMsg(blId), blDevices[blId].blIp, blDevices[blId].blKey, 'Get temperature')
    if (not ok) then return ok end

    -- extract the status from the payload
    local temperature = payloadTab[plData.temperature.msb] + payloadTab[plData.temperature.lsb]/10

    return temperature, ok
end

-- Send IR & RF messages
-- returns true if the set was successful
local function txIrRf(blId, dataTab)
    local ok, payloadTab = sendReceive(makeRMTxIrRfMsg(blId, dataTab), blDevices[blId].blIp, blDevices[blId].blKey, 'Tx IR RF')
    return ok
end

-- Send relay off/on message: SP1
-- returns true if the set was successful
local function SP1offOn(blId, offOn)
    local ok, payloadTab = sendReceive(makeSP1RelayMsg(blId, offOn), blDevices[blId].blIp, blDevices[blId].blKey, 'Relay off/on')
    return ok
end

-- Send relay off/on messageL SP2
-- returns true if the set was successful
local function SP2offOn(blId, offOn)
    local ok, payloadTab = sendReceive(makeSP2RelayMsg(blId, offOn), blDevices[blId].blIp, blDevices[blId].blKey, 'Relay off/on')
    return ok
end

-- Send relays (plural) off/on message: MP1
-- returns true if the set was successful
local function MP1offOn(blId, offOn, relay)
    local ok, payloadTab = sendReceive(makeMP1RelayMsg(blId, offOn, relay), blDevices[blId].blIp, blDevices[blId].blKey, 'Relay off/on')
    return ok
end

-- lul_device is the device ID (a number). lul_settings is a table with all the arguments to the action.
local function validatePtrs(lul_device)
    local altId = luup.devices[lul_device].id

    if (not veraDevices[altId]) then return false end
    local blId     = veraDevices[altId].blId
    local veraFunc = veraDevices[altId].veraFunc   -- look up the function
    if (veraFunc and blId) then return true, blId, veraFunc  end
    return false
end

-- service: relay on/off
local function setTarget(lul_device, newTargetValue)
    local offOn = (tonumber(newTargetValue) == 1)
    local relay = 1
    local ok, blId, veraFunc = validatePtrs(lul_device)   -- function is SP1offOn(), SP2offOn() or MP1offOn()
    if (ok) then veraFunc(blId, offOn, relay) end
end

-- service: send an IR or RF code
local function sendCode(lul_device, irRfCode)
    if (not irRfCode) then return end
    if (type(irRfCode) ~= 'string') then return end
    if (20 >= irRfCode:len()) then return end

    local ok, blId, veraFunc = validatePtrs(lul_device)   -- function is txIrRf()
    if (not ok) then return end

    local irRfCode  = irRfCode:lower()
    local pCodeTst  = irRfCode:sub(1,4)
    local blCodeTst = irRfCode:sub(1,2)
    local irCodeTab = {}

    if (pCodeTst == '0000') then
        -- Pronto code
        irCodeTab = prontoCode2blCode(irRfCode)

    -- BroadLink code 0x26 = IR, 0xd7 for RF 315MHz, 0xb2 for RF 433MHz
    elseif ((blCodeTst == '26') or (blCodeTst == 'd7') or (blCodeTst == 'b2')) then
        -- convert the ir string to a byte table
        local n = 0
        for c in irRfCode:gmatch('%x%x') do
            debug(c)
            n = tonumber(c,16)
            if (n == nil) then debug('Invalid IR code - not all hexadecimal',50) return end
            table.insert(irCodeTab, n)
        end
    else debug('Invalid IR code',50) return end

    -- for debugging purposes only
    if (DEBUG_MODE) then
        local irCodeTabHex = {}
        for _,v in ipairs(irCodeTab) do
            table.insert(irCodeTabHex, string.format('%02x', v))
        end
        debug('Broadlink IR code 2 = '..table.concat(irCodeTabHex,' '))
    end

    veraFunc(blId, irCodeTab)
end

-- service: send a Pronto code
local function sendProntoCode(lul_device, ProntoCode)
    sendCode(lul_device, ProntoCode)
end

-- map BroadLink hex ids to friendly labels
local function setBlLabels()
     blDevs = {
    [0x0000] = {desc = 'SP1'                   },
    [0x2711] = {desc = 'SP2'                   },
    [0x2719] = {desc = 'SP2'                   },
    [0x7919] = {desc = 'SP2'                   },
    [0x271a] = {desc = 'SP2'                   },
    [0x791a] = {desc = 'SP2 Honeywell'         },
    [0x753e] = {desc = 'SP3'                   },
    [0xBEEF] = {desc = 'SP3S'                  },
    [0x2720] = {desc = 'SPMini'                },
    [0x2728] = {desc = 'SPMini2'               },
    [0x2733] = {desc = 'SPMini2'               },
    [0x273e] = {desc = 'SPMini OEM'            },
    [0x2736] = {desc = 'SPMiniPlus'            },
    [0xBEEF] = {desc = 'SC1'                   },
    [0x4ef7] = {desc = 'MP1'                   },
    [0x2712] = {desc = 'RM2'                   },
    [0x2737] = {desc = 'RM Mini'               },
    [0x273d] = {desc = 'RM Pro Phicomm'        },
    [0x2783] = {desc = 'RM2 Home Plus'         },
    [0x277c] = {desc = 'RM2 Home Plus GDT'     },
    [0x272a] = {desc = 'RM2 Pro Plus'          },
    [0x2787] = {desc = 'RM2 Pro Plus 2'        },
    [0x278b] = {desc = 'RM2 Pro Plus BL'       },
    [0x278f] = {desc = 'RM Mini Shate'         },
    [0xBEEF] = {desc = 'TC2'                   },
    [0x2714] = {desc = 'A1'                    },
    [0x2722] = {desc = 'S1 SmartOne Alarm Kit' },
    [0x4e4d] = {desc = 'Dooya DT360E'          }
    }
end

-- Map BroadLink functionality to the functions that will do the actual work. Stick
-- all this stuff here, so we don't end up with forward references to the called functions
local function setDeviceConfiguration()
    setBlLabels()
    -- add in the empty devs arrays, then fill them in
    for k,_ in pairs(blDevs) do blDevs[k].devs = {} end

    local ptr = nil
    blDevs[0x0000].devs.rly1 = SP1offOn                        -- 'SP1'
    blDevs[0x2711].devs.rly1 = SP2offOn                        -- 'SP2'
    blDevs[0x2719].devs.rly1 = SP2offOn                        -- 'SP2'
    blDevs[0x7919].devs.rly1 = SP2offOn                        -- 'SP2'
    blDevs[0x271a].devs.rly1 = SP2offOn                        -- 'SP2'
    blDevs[0x791a].devs.rly1 = SP2offOn                        -- 'SP2 Honeywell'
    blDevs[0x753e].devs.rly1 = SP2offOn                        -- 'SP3'
    ptr = blDevs[0xBEEF].devs                                  -- 'SP3S'
        ptr.rly1 = SP2offOn                                    --
        ptr.em1  = nil                   -- has energy meter   --
    blDevs[0x2720].devs.rly1 = SP2offOn                        -- 'SPMini'
    blDevs[0x2728].devs.rly1 = SP2offOn                        -- 'SPMini2'
    blDevs[0x2733].devs.rly1 = SP2offOn                        -- 'SPMini2'
    blDevs[0x273e].devs.rly1 = SP2offOn                        -- 'SPMini OEM'
    blDevs[0x2736].devs.rly1 = SP2offOn                        -- 'SPMiniPlus'
    blDevs[0xBEEF].devs.rly1 = nil                             -- 'SC1'
    ptr = blDevs[0x4ef7].devs                                  -- 'MP1'
        ptr.rly1 = MP1offOn                                    --
        ptr.rly2 = MP1offOn                                    --
        ptr.rly3 = MP1offOn                                    --
        ptr.rly4 = MP1offOn                                    --
    blDevs[0x2712].devs.ir = txIrRf                            -- 'RM2'
    blDevs[0x2737].devs.ir = txIrRf                            -- 'RM Mini'
    ptr = blDevs[0x273d].devs                                  -- 'RM Pro Phicomm'
        ptr.ir   = txIrRf                                      --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x2783].devs                                  -- 'RM2 Home Plus'
        ptr.ir   = txIrRf                                      --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x277c].devs                                  -- 'RM2 Home Plus GDT'
        ptr.ir   = txIrRf                                      --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x272a].devs                                  -- 'RM2 Pro Plus'
        ptr.ir   = txIrRf                                      --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x2787].devs                                  -- 'RM2 Pro Plus 2'
        ptr.ir    = txIrRf                                     --
        ptr.temp  = getTemperature                             --
        ptr.rf315 = txIrRf                                     --
        ptr.rf433 = txIrRf                                     --
    ptr = blDevs[0x278b].devs                                  -- 'RM2 Pro Plus BL'
        ptr.ir   = txIrRf                                      --
        ptr.temp = getTemperature                              --
    blDevs[0x278f].devs.ir = txIrRf                            -- 'RM Mini Shate'
    ptr = blDevs[0xBEEF].devs                                  -- 'TC2'
        ptr.ir    = rly1                                       --
        ptr.rf315 = txIrRf                                     --
        ptr.rf433 = txIrRf                                     --
    ptr = blDevs[0x2714].devs                                  -- 'A1'
        ptr.humidity   = nil                                   --
        ptr.lightLevel = nil                                   --
        ptr.noise      = nil                                   --
        ptr.temp       = nil                                   --
        ptr.voc        = nil                                   --
    ptr = blDevs[0x2722].devs                                  -- 'S1 SmartOne Alarm Kit'
        ptr.keyFob       = nil                                 -- Note: polling is to slow to make this item viable
        ptr.motionSensor = nil                                 -- Note: polling is to slow to make this item viable
        ptr.doorSensor   = nil                                 -- Note: polling is to slow to make this item viable
    ptr = blDevs[0x4e4d].devs                                  -- 'Dooya DT360E'
        -- add in whatever a 'Dooya DT360E' does here          --
end

-- The user may have changed the original Vera device description as seen in the UI.
-- Update our local copy.
local function updateVeraDesc()
    for veraDeviceId in broadLinkBasedVeraDevices() do
        local altId = luup.devices[veraDeviceId].id       -- id is labelled altid in the UI
        veraDevices[altId].veraDesc = luup.devices[veraDeviceId].description
    end
end

-- Poll the BroadLink device for data. Function needs to be global.
function pollBroadLinkDevices()
    if (m_PollEnable ~= '1') then return end

    -- poll sensors: temperature, humidity, etc contained in all the discovered BroadLink devices
    -- altId is of the form: 'xx:xx:xx:xx:xx:xx_temp' where thee xx make up the mac address
    for veraDeviceId in broadLinkBasedVeraDevices() do
        local altId = luup.devices[veraDeviceId].id       -- id is labelled altid in the UI

        debug('veraDeviceId')
        debug(veraDeviceId)
        debug(altId)
        debug(veraDevices[altId])

        if (not veraDevices[altId]) then return end
        local blId     = veraDevices[altId].blId
        local sensor   = veraDevices[altId].veraDevice
        local veraFunc = veraDevices[altId].veraFunc   -- look up the function to be used for this device

        debug(blId)
        debug(sensor)
        debug(veraFunc)

        -- make sure we have a BroadLink device and an associated function and then go poll all the sensors found
        if (blId and veraFunc and sensor) then
            if     (sensor == DEV.DOOR_SENSOR)        then updateVariable('Tripped',            veraFunc(blId), SID.DOOR_SENSOR,        veraDeviceId)
            elseif (sensor == DEV.GENERIC_SENSOR)     then updateVariable('CurrentLevel',       veraFunc(blId), SID.GENERIC_SENSOR,     veraDeviceId)
            elseif (sensor == DEV.HUMIDITY_SENSOR)    then updateVariable('CurrentLevel',       veraFunc(blId), SID.HUMIDITY_SENSOR,    veraDeviceId)
            elseif (sensor == DEV.LIGHT_SENSOR)       then updateVariable('CurrentLevel',       veraFunc(blId), SID.LIGHT_SENSOR,       veraDeviceId)
            elseif (sensor == DEV.MOTION_SENSOR)      then updateVariable('Tripped',            veraFunc(blId), SID.MOTION_SENSOR,      veraDeviceId)
            elseif (sensor == DEV.SMOKE_SENSOR)       then updateVariable('Tripped',            veraFunc(blId), SID.SMOKE_SENSOR,       veraDeviceId)
            elseif (sensor == DEV.TEMPERATURE_SENSOR) then updateVariable('CurrentTemperature', veraFunc(blId), SID.TEMPERATURE_SENSOR, veraDeviceId)
            -- add in more sensors here
            else debug(veraDevices[altId].veraDesc..': device is not a sensor or if a sensor; is not coded for')
            end
        end
    end

--[[
    -- do we want this?
    local timeStamp = os.time()
    updateVariable('LastUpdate', timeStamp, SID.HA)

    local timeFormat = '%F %X'
    debug('Last update: '..os.date(timeFormat, timeStamp))

    timeFormat = '%H:%M'
    updateVariable('LastUpdateHr', os.date(timeFormat, timeStamp))
]]

    -- get the info contained in all the BroadLink devices every poll interval
    luup.call_delay('pollBroadLinkDevices', m_PollInterval)
end

-- User service: polling on off
local function polling(pollEnable)
    if (not ((pollEnable == '0') or (pollEnable == '1'))) then return end
    m_PollEnable = pollEnable
    updateVariable('PollEnable', m_PollEnable)
end

-- OK lets do it
function luaStartUp(lul_device)
    THIS_LUL_DEVICE = lul_device
    debug('Initialising plugin: '..PLUGIN_NAME)

    -- Lua ver 5.1 does not have bit functions, whereas ver 5.2 and above do. Not
    -- that this matters in this code but it's nice to know if anything changes.
    debug('Using: '.._VERSION)

    -- set up some defaults:
    updateVariable('PluginVersion', PLUGIN_VERSION)

    -- set up some defaults:
    local debugEnabled = luup.variable_get(PLUGIN_SID, 'DebugEnabled', THIS_LUL_DEVICE)
    if ((debugEnabled == nil) or (debugEnabled == '')) then
        debugEnabled = '0'
        updateVariable('DebugEnabled', debugEnabled)
    end
    DEBUG_MODE = (debugEnabled == '1')

    local pluginEnabled = luup.variable_get(PLUGIN_SID, 'PluginEnabled', THIS_LUL_DEVICE)
    if ((pluginEnabled == nil) or (pluginEnabled == '')) then
        pluginEnabled = '1'
        updateVariable('PluginEnabled', pluginEnabled)
    end

    OUR_IP = getOurIPaddress()
    setDeviceConfiguration()

    -- Works ok but is not called any where; testing only
    -- However it would be called like this, in this sort of framework.
    -- sendPairingMsg()

    broadcastDiscoverDevicesMsg()

    if ((pollEnable == nil) or (pollEnable == '')) then
        -- turn the polling on
        m_PollEnable = '1'
        polling(m_PollEnable)
    else
        m_PollEnable = pollEnable
    end

    -- don't allow polling any faster than five minutes
    local theInterval = tonumber(pollInterval)
    if ((theInterval == nil) or (theInterval < FIVE_MIN_IN_SECS)) then
        m_PollInterval = FIVE_MIN_IN_SECS
        updateVariable('PollInterval', tostring(FIVE_MIN_IN_SECS))
    else
        m_PollInterval = theInterval
    end

    -- make a child for each device found as part of each BroadLink device
    local child_devices = luup.chdev.start(THIS_LUL_DEVICE)

--[[
    Add child devices:

    The child D_*.xml files each specify a "serviceList" with a link to the associated S_*.xml file containing
    the actionList. With the parent "handleChildren" set to one, the child serviceList handled by the parent.
    It contains the link to the "implementation file: I_*.xml" holding the interfaces and the run time code or
    a link to that code.

    If the parent device specifies: <handleChildren>1</handleChildren> then child
    devices do not need an implementation file. If the Device file includes:
    <implementationFile>I_PluginName.xml</implementationFile> then the implementation file
    does not need to be additionally specified when the child is created.

    The device file references the service files (S_) and gives each service a serviceType
    and a serviceId. The serviceType what defines the standard UPnP service. But since it's
    possible to have multiple instances of a given service, so each needs a unique serviceId.

    Also see:
        http://forum.micasaverde.com/index.php/topic,34305.msg252587.html#msg252587
        http://forum.micasaverde.com/index.php/topic,1503.msg5433.html#msg5433
]]
    for k,v in pairs(veraDevices) do
        luup.chdev.append(
            THIS_LUL_DEVICE,
            child_devices,
            k,              -- altid
            v.veraDesc,     -- name
            v.veraDevice,   -- device type
            v.veraFile,     -- device filename
            '',             -- implementation filename
            '',             -- parameters
            false)          -- embedded
    end
    luup.chdev.sync(THIS_LUL_DEVICE, child_devices)

    -- keep track of any users changes to the device descrtions
    updateVeraDesc()

    -- Now all the BroadLink devices have been discovered.
    -- We can go get all the authorisation info.
    for k,_ in pairs(blDevices) do
        getAuthorisation(k)
    end

--[[
    Test code only:

    local altId = 'xx:xx:xx:xx:xx:xx_ir'
    local lul_device_TEST = {id = altId}

    -- Sony generated mute code
    local leadIn = '0000 0067 0000 001A'
    local code = '0060 0018 0018 0018 0018 0018 0030 0018 0018 0018 0030 0018 0018 0018 0018 0018 0030 0018 0018 0018 0018 0018 0018 0018 0018 0426'
    local pCode = leadIn..' '..code..' '..code
    local blCode = '26003a004e1414141414271414142714141414142714141414141414140003634e1414141414271414142714141414142714141414141414140003630d05'
    sendCode(lul_device_TEST, pCode)
    sendCode(lul_device_TEST, blCode)
]]

    -- delay so that the first poll occurs delay interval after start up
    local INITIAL_POLL_INTERVAL_SECS = 90
    luup.call_delay('pollBroadLinkDevices', INITIAL_POLL_INTERVAL_SECS)

    -- required for UI7. UI5 uses true or false for the passed parameter.
    -- UI7 uses 0 or 1 or 2 for the parameter. This works for both UI5 and UI7
    luup.set_failure(false)

    return true, 'All OK', PLUGIN_NAME
end

-- test code only
-- luaStartUp(nil)
-- return true
