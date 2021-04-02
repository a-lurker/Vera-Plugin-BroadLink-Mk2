-- a-lurker, copyright 2017, 2018, 2019, 2020 and 2021
-- First release 10 December 2017; updated  April 2021

-- Tested on openLuup

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
    Typically the BroadLink device is already paired with the phone app. The following is just
    further information on pairing in general.

    On purchase the BroadLink device is in a mode where it can be configured via a mobile phone.
    We need to change the mode to AP mode. Place the BroadLink device into AP mode by holding
    down the reset button about four seconds. A successful change to AP mode is indicated by the
    blue LED: four slow flashes followed by a one second pause.

    At this point the device acts as WiFi access point (AP). It runs a DCHP server on 192.168.10.1
    Any Vera, PC, etc, that connects to the AP, will be given an address of 192.168.10.2, which will
    increment, as further devices are connected to the AP.

    We need to send a pairing message to the AP on 192.168.10.1 In this pairing message, we
    send the WiFi SSID and password of the AP that is part of our Vera network. Once successfully
    received, the BroadLink device with disable its own AP and DCHP server and connect to the AP
    specified in our message ie the LAN connected to Vera. The blue LED goes completely off.
    The BroadLink device effectively stops acting as an AP and changes to being a slave device.
    At this point we can start to use the facilities the BroadLink device offers.
    Refer to: sendPairingMsg(), which works but is not called by this code.

    Devices use broadcast and multicast on 224.0.0.251

    Refs:
       https://github.com/mjg59/python-broadlink
       https://github.com/lprhodes/broadlinkjs-rm/blob/master/index.js
       https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1
       https://github.com/sayzard/BroadLinkESP/blob/master/BroadLinkESP.cpp
       https://github.com/mob41/broadlink-java-api/tree/master/src/main/java/com/github/mob41/blapi
]]

local PLUGIN_NAME      = 'BroadLink_Mk2'
local PLUGIN_SID       = 'urn:a-lurker-com:serviceId:'..PLUGIN_NAME..'_1'
local PLUGIN_VERSION   = '0.57'
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
local SCAN_PERIOD      = MSG_TIMEOUT + 1   -- in seconds: don't make this any lower

local CHECKSUM_SEED    = 0xbeaf
local FIVE_MIN_IN_SECS = 300
local m_PollInterval   = FIVE_MIN_IN_SECS
local m_PollEnable     = ''    -- is set to either: '0' or '1'
local m_PollLastState  = ''
local m_msgCount       = -1
local m_doEncodeDecode = true  -- used for testing purposes only
local m_json           = nil
local m_IRScanCount    = 0
local m_RFScanCount    = 0

local RF = {
    START_GET_FREQ = 1,
    SCAN_FOR_FREQ  = 2,
    START_GET_CODE = 3,
    SCAN_FOR_CODE  = 4,
    DONE           = 5,
    ABORT_1        = 6,
    ABORT_2        = 7
}
local m_RfScanningState = RF.START_GET_FREQ

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
    off            = 0x00,   -- cmd = 0x6a, 4 byte payload
    on             = 0x01,   -- cmd = 0x6a, 4 byte payload

    get            = 0x01,   -- cmd = 0x6a, 16 byte payload
    set            = 0x02,   -- cmd = 0x6a, 4 byte + payload size ie off, on, ir/rf data: location 0x05 = 0x26 for ir data, else rf data
    irLearnStart   = 0x03,   -- cmd = 0x6a, 16 byte payload
    irGetCode      = 0x04,   -- cmd = 0x6a, 16 byte payload   NOTE: same as 'rfScanForCode'
    sensorsGet     = 0x06,   -- cmd = 0x6a, 16 byte payload
    sensorsSet     = 0x07,   -- cmd = 0x6a, 16 byte payload
    energyGet      = 0x08,   -- cmd = 0x6a, 16 byte payload
    dooya          = 0x09,   -- cmd = 0x6a, 16 byte payload
    mp1RlyStatus   = 0x0a,   -- cmd = 0x6a, 16 byte payload
    mp1RlySw       = 0x0d,   -- cmd = 0x6a, 16 byte payload
    rfStartGetFreq = 0x19,   -- cmd = 0x6a, 16 byte payload
    rfScanForFreq  = 0x1a,   -- cmd = 0x6a, 16 byte payload
    rfStartGetCode = 0x1b,   -- cmd = 0x6a, 16 byte payload
    rfScanForCode  = 0x04,   -- cmd = 0x6a, 16 byte payload   NOTE: same as 'irGetCode'
    rfLearnStop    = 0x1e    -- cmd = 0x6a, 16 byte payload
}

-- returned data typically starts at the 5th byte (0x04+1) of the payload
local plData = {
    status      =  0x04+1,
    irCodeIdx0  =  0x04+1,
    rfCodeIdx0  =  0x04+1,
    rfFoundFlag =  0x04+1,
    energy      = {msb = 0x07+1, isb = 0x06+1, lsb = 0x05+1},
    temperature = {msb = 0x04+1, lsb = 0x05+1},
    humidity    = {msb = 0x06+1, lsb = 0x07+1},
    lightLevel  =  0x08+1,
    airQuality  =  0x0a+1,
    noiseLevel  =  0x0c+1
}

--[[
    This look up table describes the capabilities of a physical Broadlink device and has ptrs to the associated
    functions. An example element in the blDevs table is shown below. The index is the internal hex number
    that represents each type of Broadlink device. In the example 0x2787 is the value for a 'RM2 Pro Plus 2'

    blDeviceType = 0x2787
    blDevs[blDeviceType].desc       = 'RM2 Pro Plus 2'
    blDevs[blDeviceType].devs.ir    = ctrlrRf           -- ptr to ctrlrRf function
    blDevs[blDeviceType].devs.temp  = getTemperature    -- ptr to getTemperature function
    blDevs[blDeviceType].devs.rf315 = ctrlrRf           -- ptr to ctrlrRf function
    blDevs[blDeviceType].devs.rf433 = ctrlrRf           -- ptr to ctrlrRf function
    blDevs[blDeviceType].plHdrs     = {0x0004, 0x000da} -- payload protocol headers (when applicable)
]]

local blDevs = {}

--[[
blDevices[blId] = {   -- blId, string, the id of a BroadLink physical device: we'll use the BroadLink device's mac address

    -- the following is derived from broadcasted discovery process
    blIp           = ip,                         -- string: ip address of  the host BroadLink device
    blDeviceType   = blDeviceType,               -- number: id of the host BroadLink device 'type'
    blDesc         = blDevs[blDeviceType].desc,  -- string: description of the host BroadLink device eg "RM pro", etc

    -- the following is derived from authorisation process
    blInternalId   = internalId,                 -- string: the id  returned from the BroadLink host device during the authorisation process
    blKey          = key                         -- string: the key returned from the BroadLink host device during the authorisation process
}
]]

local blDevices = {}

--[[
All the Vera devices eg: temperature sensors, relays, etc and in which physical BroadLink device they are located

veraDevices[altId] = {   -- altId, as used by the this vera plugin, of the form: host mac address plus the vera function type
    blId           = blId,                       -- the id of the BroadLink parent device - which is simply its mac address
    veraDesc       = veraDesc,                   -- vera device description, as seen in the user interface
    veraDevice     = dev,                        -- vera device type - for child creation
    veraFile       = file,                       -- vera device file - for child creation
    veraFunc       = func,                       -- vera device function
    veraId         = lul_device.id               -- vera device's id
}
]]

local veraDevices = {}

-- http://w3.impa.br/~diego/software/luasocket/reference.html
local socket = require('socket')

local SHOW_AES = false

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

-- If non existent, create the variable. Update
-- the variable, only if it needs to be updated
local function updateVariable(varK, varV, sid, id)
    if (sid == nil) then sid = PLUGIN_SID      end
    if (id  == nil) then  id = THIS_LUL_DEVICE end

    if (varV == nil) then
        if (varK == nil) then
            luup.log(PLUGIN_NAME..' debug: '..'Error: updateVariable was supplied with nil values', 1)
        else
            luup.log(PLUGIN_NAME..' debug: '..'Error: updateVariable '..tostring(varK)..' was supplied with a nil value', 1)
        end
        return
    end

    local newValue = tostring(varV)
    debug(newValue..' --> '..varK)

    local currentValue = luup.variable_get(sid, varK, id)
    if ((currentValue ~= newValue) or (currentValue == nil)) then
        luup.variable_set(sid, varK, newValue, id)
    end
end

-- If possible, get a JSON parser. If none available, returns nil. Note that typically UI5 may not have a parser available.
local function loadJsonModule()
    local jsonModules = {
        'rapidjson',            -- how many json libs are there?
        'cjson',                -- openLuup?
        'dkjson',               -- UI7 firmware
        'openLuup.json',        -- https://community.getvera.com/t/pure-lua-json-library-akb-json/185273
        'akb-json',             -- https://community.getvera.com/t/pure-lua-json-library-akb-json/185273
        'json',                 -- OWServer plugin
        'json-dm2',             -- dataMine plugin
        'dropbox_json_parser',  -- dropbox plugin
        'hue_json',             -- hue plugin
        'L_ALTUIjson'           -- AltUI plugin
    }

    local ptr  = nil
    local json = nil
    for n = 1, #jsonModules do
        -- require does not load the module, if it's already loaded
        -- Vera has overloaded require to suit their requirements, so it works differently from openLuup
        -- openLuup:
        --    ok:     returns true or false indicating if the module was loaded successfully or not
        --    result: contains the ptr to the module or an error string showing the path(s) searched for the module
        -- Vera:
        --    ok:     returns true or false indicating the require function executed but require may have or may not have loaded the module
        --    result: contains the ptr to the module or an error string showing the path(s) searched for the module
        --    log:    log reports 'luup_require can't find xyz.json'
        local ok, result = pcall(require, jsonModules[n])
        ptr = package.loaded[jsonModules[n]]
        if (ptr) then
            json = ptr
            debug('Using: '..jsonModules[n])
            break
        end
    end
    if (not json) then debug('No JSON library found') return json end
    return json
end

-- Log the outcome (hex) - only used for testing
local function tableDump(userMsg, byteTab)
    if (not DEBUG_MODE) then return end

    if (byteTab == nil) then debug(userMsg..' is nil') return end
    local tabLen = #byteTab

    local hex = ''
    local asc = ''
    local hexTab = {}
    local ascTab = {'   '}
    local dmpTab = {userMsg..'\n\n'}

    for i=1, tabLen do
        local ord = byteTab[i]
        hex = string.format("%02X", ord)
        asc = '.'
        if ((ord >= 32) and (ord <= 126)) then asc = string.char(ord) end

        table.insert(hexTab, hex)
        table.insert(ascTab, asc)

        if ((i % 16 == 0) or (i == tabLen))then
            table.insert(ascTab,'\n')
            table.insert(dmpTab,table.concat(hexTab, ' '))
            table.insert(dmpTab,table.concat(ascTab))
            hexTab = {}
            ascTab = {'   '}
        elseif (i % 8 == 0) then
            table.insert(hexTab, '')
            table.insert(ascTab, '')
        end
    end

    debug(table.concat(dmpTab))
end

-- https://gist.github.com/bortels/1436940
-- Lua 5.1+ base64 v3.0 (c) 2009 by Alex Kloss <alexthkloss@web.de>
-- licensed under the terms of the LGPL2
-- base64 decoding. We could use this function found in the mime library: mime.unb64(data) but we won't.
local function base64dec(data)
    -- character table string
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then return '' end
        local r,f='',(b:find(x)-1)
        for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
        return r;
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then return '' end
        local c=0
        for i=1,8 do c=c+(x:sub(i,i)=='1' and 2^(8-i) or 0) end
        --return string.char(c)   --  as binary
        return string.format('%02x',c)   -- as hex string
    end))
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
    local checksum = CHECKSUM_SEED
    for i = 1, #msgTab do checksum = checksum + msgTab[i] end
    local overflow = math.floor(checksum / 0x10000)
    checksum = checksum - (overflow * 0x10000)
    insertMsbLsb(msgTab, idxChkSum, checksum)
end

-- Overall checksum ok?
local function validChecksum(rxMsgTab)
    -- get the checksum in the returned message
    local msgCheckum = rxMsgTab[idxChkSum.msb]*256 + rxMsgTab[idxChkSum.lsb]

    -- zero it out before rechecking
    rxMsgTab[idxChkSum.msb], rxMsgTab[idxChkSum.lsb] = 0x00, 0x00

    local checksum = CHECKSUM_SEED
    for i = 1, #rxMsgTab do checksum = checksum + rxMsgTab[i] end
    local overflow = math.floor(checksum / 0x10000)
    checksum = checksum - (overflow * 0x10000)
    return msgCheckum == checksum
end

-- Payloads have their own checksum, which is calculated and inserted in the header before the payload is encrypted
local function insertPayloadChecksum(headerTab, payloadTab)
    local checksum = CHECKSUM_SEED
    for i = 1, #payloadTab do checksum = checksum + payloadTab[i] end
    local overflow = math.floor(checksum / 0x10000)
    checksum = checksum - (overflow * 0x10000)
    insertMsbLsb(headerTab, idxPayloadChkSum, checksum)
end

-- Payload checksum ok?
local function validPayloadChecksum(rxMsgTab, payloadTab)
    -- get the checksum in the returned message
    local payloadCheckum = rxMsgTab[idxPayloadChkSum.msb]*256 + rxMsgTab[idxPayloadChkSum.lsb]

    local checksum = CHECKSUM_SEED
    for i = 1, #payloadTab do checksum = checksum + payloadTab[i] end
    local overflow = math.floor(checksum / 0x10000)
    checksum = checksum - (overflow * 0x10000)
    return payloadCheckum == checksum
end

-- Insert payload header for devices that require it
local function insertPayloadHeader(payloadTab, type, blId)
  local plHdrs = blDevs[blDevices[blId].blDeviceType].plHdrs
  if plHdrs == nil then return end

  for i=#payloadTab, 1, -1 do
    payloadTab[i+2] = payloadTab[i]
  end
  insertMsbLsb(payloadTab, {msb = 0x00+2, lsb = 0x00+1}, plHdrs[type])
end

-- Remove payload header for devices that require it
local function removePayloadHeader(payloadTab, blId)
  local hdrLen = blDevs[blDevices[blId].blDeviceType].plHdrs and 2 or 0
  for i=hdrLen+1, #payloadTab do
    payloadTab[i] = payloadTab[i+hdrLen]
  end
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
    local zeroTab = {}
    -- set the table to all nulls
    for i = 1, length do zeroTab[i] = 0x00 end
    return zeroTab
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

    if (DEBUG_MODE and SHOW_AES and encrypt) then
        debug ('AES inputStr length = '..tostring(inputStr:len()))
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

    -- https://wiki.openssl.org/index.php/Enc
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
    if (SHOW_AES) then debug (encDecCmd) end

    -- capture the stdout data
    local pipeOut   = assert(io.popen(encDecCmd, 'r'))
    local outputStr = assert(pipeOut:read('*a'))
    pipeOut:close()

    if (DEBUG_MODE and SHOW_AES and not encrypt) then
        debug ('AES outputStr length = '..tostring(outputStr:len()))
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
    https://community.getvera.com/t/gc100-pronto-code/191951/10

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
    The response contains the 48 bytes we sent with makeDiscoverDevicesMsg() with an
    updated checksum, plus another 80 bytes of info, making a total of 128 bytes.

    0x26+1 = 0x7 reply to "discoverDevices" request blCmds.discoverDevices.rx
    0x35+1 to 0x34+1 = device type eg as 2 bytes indicating "RM2 Pro Plus 2" etc. This determines capabilities.
    0x39+1 to 0x36+1 = ip  address   NOTE: some devices eg RM PRO stores this little-endian; others eg SC1 relay stores this big-endian
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

    tableDump('Rx\'ed a discovery response: rxMsg length = '..tostring(rxMsgLen), rxMsgTab)

    -- sanity checks - sometimes the "Android RM bridge" or a router will trigger the first check here
    if (rxMsgLen ~= 128) then debug('Error: discovery msg - incorrect size: '..ip,50) return end
    if (rxMsgTab[0x26+1] ~= blCmds.discoverDevices.rx) then debug('Error: discovery msg - reply id incorrect',50) return end

    if (rxMsgTab[128] == 0x00) then
        debug('Looks like the Cloud bit is not set - that\'s good',50)
    else
        debug('Looks like the Cloud bit is set - that\'s not good',50)
    end

    -- get the mac address contained in the returned message
    local strTab = {}
    for i = 0x3f+1, 0x3a+1, -1 do table.insert(strTab, string.format('%02x',rxMsgTab[i])) end

    -- get the mac address and use it as part of a BroadLink device blId and the Vera device altId
    -- indices are case sensitive, so force to lower just in case
    local mac = string.lower(table.concat(strTab,':'))
    local blId = mac

    -- get the device's friendly text name
    strTab = {}
    local i = 0x40+1
    while ((rxMsgTab[i] ~= 0x00) and (i ~= 127)) do
       table.insert(strTab, string.format('%02x',rxMsgTab[i]))
       i = i+1
    end
    debug('Friendly name: '..table.concat(strTab,''))

    -- get the hex number that represents this particular BroadLink device
    local blDeviceType = rxMsgTab[0x35+1]*256 + rxMsgTab[0x34+1]

    if (not blDevs[blDeviceType]) then
        debug(string.format('The BroadLink device at IP address %s and of type 0x%04x is not known to this plugin', ip, blDeviceType),50)
        return
    end

    blDevices[blId] = {
        blIp         = ip,
        blDeviceType = blDeviceType,
        blDesc       = blDevs[blDeviceType].desc,

        -- the following will be filled in during the authorisation process
        blInternalId = '????',
        blKey        = initialKey
    }

    debug(blId)   -- the BroadLink device mac address
    debug(blDevices[blId].blIp)
    debug(string.format('BroadLink device type: 0x%04x', blDevices[blId].blDeviceType))
    debug(blDevices[blId].blDesc)
    debug(blDevices[blId].blInternalId)
    debug(blDevices[blId].blKey)
end

-- Make the BroadLink "payload" header
local function makeCmdHeader(blId, payloadTab, command)
    local headerTab = makeEmptyTable(0x38)   -- 56 bytes long

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
    insertMsbLsb(headerTab, idxDeviceId, blDevices[blId].blDeviceType)

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
    for c in blId:gmatch('%x%x') do
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

    -- we pass in the payloadTab, so the payload's own checksum can be calculated and inserted into the main header
    local msgTab = makeCmdHeader(blId, payloadTab, command)

    tableDump('Header to be sent follows (ex checksum):', msgTab)
    tableDump('Payload to be sent follows (unencrypted):', payloadTab)

    local encodedTab = encryptDecrypt(blDevices[blId].blKey, payloadTab, true)

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
-- https://github.com/mjg59/python-broadlink/blob/daebd806fd8529b9c29b4d70f82a036f30ea5847/broadlink/__init__.py#L1077
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
    msgTab[0x84+1] = ssidLen             -- insert ssid length
    msgTab[0x85+1] = passLen             -- insert pw length
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
    local payloadTab = makeEmptyTable(0x50)   -- 80 bytes long

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

-- A simple single byte command message to readWrite.tx = 0x6a
local function makeSimpleMsg(blId, packetLength, command)
    local payloadTab = makeEmptyTable(packetLength)
    payloadTab[0x00+1] = command
    -- insert payload "request" header
    insertPayloadHeader(payloadTab, 1, blId)
    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink SP1 "single relay off/on" message
local function makeSP1RelayMsg(blId, offOn)
    local payloadTab = makeEmptyTable(0x04)   -- 4 bytes long

    -- we'll issue the off/on command
    payloadTab[0x00+1] = plCmds.off

    -- on selected
    if (offOn) then payloadTab[0x00+1] = plCmds.on end

    return headerAndPayload(blId, payloadTab, blCmds.sp1.tx)
end

-- Make the BroadLink SP2 "single relay off/on" message
local function makeSP2RelayMsg(blId, offOn)
    local payloadTab = makeEmptyTable(0x10)   -- 16 bytes long

    -- we'll issue the off/on command
    payloadTab[0x00+1] = plCmds.set
    payloadTab[0x04+1] = plCmds.off

    -- on selected
    if (offOn) then payloadTab[0x04+1] = plCmds.on end

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink "get energy" message
local function makeGetEnergyMsg(blId)
    local payloadTab = makeEmptyTable(0x0a)   -- 10 bytes long

    -- we'll issue the get energy command: Watt-hour (Wh)
    payloadTab[0x00+1] = plCmds.energyGet
    payloadTab[0x02+1] = 0xfe   -- 254d
    payloadTab[0x03+1] = 0x01
    payloadTab[0x04+1] = 0x05
    payloadTab[0x05+1] = 0x01
    payloadTab[0x09+1] = 0x2d   -- 45d

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink "IR & RF" message
local function makeTxIrRfMsg(blId, irRfCodeTab)
    -- UDP_MAX_PAYLOAD Warning: a host is not required to receive a datagram
    -- larger than 576 byte. So far not an issue with the BroadLink devices.

    -- length of the payload = 0x04 = 4dec + passed in data
    local payloadTab = makeEmptyTable(0x04)

    -- we'll issue the set command
    payloadTab[0x00+1] = plCmds.set

    -- Insert "data send" payload header
    insertPayloadHeader(payloadTab, 2, blId)

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
    local payloadTab = makeEmptyTable(0x10)   -- 16 bytes long

    -- we'll issue the mp1Strip relay command
    payloadTab[0x00+1] = plCmds.mp1RlySw
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
    for i = 2, relay-1 do swMask = swMask*2 end

    -- on selected
    if (offOn) then
        payloadTab[0x06+1] = 0xb2 + (swMask*2)
        payloadTab[0x0e+1] = swMask
    end

    return headerAndPayload(blId, payloadTab, blCmds.readWrite.tx)
end

-- Make the BroadLink "read power" message for a MP1 power strip
local function makeMP1StatusMsg(blId)
    local payloadTab = makeEmptyTable(0x10)   -- 16 bytes long

    -- we'll issue the mp1Strip read power command
    payloadTab[0x00+1] = plCmds.mp1RlyStatus
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
local function sendReceive(msgType, txMsgTab, blId)
    local ok = false

    -- these values are used by the pairing message
    local ipAddress = BROADLINK_AP_IP
    local key       = nil

    -- everything else needs the device's ip address and key
    if (blId) then
        ipAddress = blDevices[blId].blIp
        key       = blDevices[blId].blKey
    end

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

    debug('Sending:  '..msgType..': txMsg length = '..txMsgLen)

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

    local deviceMsg = string.format('%02x%02x', rxMsgTab[0x25+1], rxMsgTab[0x24+1])
    local replyMsg  = string.format('%02x%02x', rxMsgTab[0x27+1], rxMsgTab[0x26+1])
    debug('Broadlink device: '..deviceMsg..' replied with: '..replyMsg)

    -- have a look at the error information returned
    -- 0xfff9 means an error of some sort. Seems to occur if the WiFi signal is marginal. The payload will be nil.
    -- 0xfff6 is returned when no IR/RF code has been learnt? The payload will be nil.
    local errorMsg = string.format('%02x%02x', rxMsgTab[0x23+1], rxMsgTab[0x22+1])
    if (errorMsg ~= '0000') then debug('Error: errorMsg = '..errorMsg,50) return ok end
    -- HACK if ((errorMsg ~= '0000') and (errorMsg ~= 'fff6')) then debug('Error: errorMsg = '..errorMsg,50) return ok end

    if (not validChecksum(rxMsgTab)) then debug('Error: rx\'ed msg checksum incorrect',50) return ok end

    -- get the header ready just for debugging
    local headerTab = {}
    for i=1, 0x37+1 do headerTab[i] = rxMsgTab[i] end

    -- get the received payload starting at 56d=0x38 (zero based count as per the references)
    -- it may or may not be (ie "pairing msg response") encrypted
    local rxedPayloadTab = {}
    for i = 0x38+1, rxMsgLen do table.insert(rxedPayloadTab, rxMsgTab[i]) end
    if (#rxedPayloadTab == 0) then
        debug('Received: '..msgType..': rxMsg length = '..tostring(rxMsgLen))
        tableDump('No payload found. Header follows:', headerTab)
        return ok
    end

    -- decrypt the payload
    -- The "pairing" message doesn't encrypt/decrypt, so the key passed into this function will be
    -- nil on that occasion. Before authorisation is completed, the key will equal the "initialKey".
    -- After authorisation it will be the key supplied by the discovery process.
    local payloadTab = {}
    if (m_doEncodeDecode and key) then
        payloadTab = encryptDecrypt(key, rxedPayloadTab, false)
    else  -- payload is not encrypted
        payloadTab = rxedPayloadTab
    end

    if ((#payloadTab > 0) and (not validPayloadChecksum(rxMsgTab, payloadTab))) then debug('Error: rx\'ed payload checksum incorrect',50) return ok end

    -- show the full received message complete with decrypted payload
    tableDump('Received: '..msgType..': rxMsg length = '..tostring(rxMsgLen)..' decrypted msg follows:',  headerTab)
    tableDump('Rx\'ed payload follows:', payloadTab)

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
    local ok = sendReceive('Pairing', makePairingMsg())
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
    debug('Broadcasting discovery message')
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

            -- as the responses to the broadcast are rx'ed, add the devices to the list
            addToBroadlinkPhysicalDevicesList(rxMsg, ipOrErrorMsg)
        end
    until (not rxMsg)
    
    local devCnt = 0
    for k,v in pairs(blDevices) do
        devCnt = devCnt+1
    end

    debug('Number of BroadLink devices found is '..tostring(devCnt),50)

    udp:close()

    return ok
end

-- Send the "auth" message to each BroadLink devices. This loads blKey & blInternalId
local function getAuthorisation()
    for blId,_ in pairs(blDevices) do
        local ok, payloadTab = sendReceive('Authorisation', makeAuthorisationMsg(blId), blId)
        if (ok) then
            -- extract the blInternalId from the response
            local strTab = {}
            for i = 3+1, 0+1, -1 do table.insert(strTab, string.format('%02x', payloadTab[i])) end
            blDevices[blId].blInternalId = table.concat(strTab)

            -- extract the key from the response
            strTab = {}
            for i = 4+1, 19+1 do table.insert(strTab, string.format('%02x', payloadTab[i])) end
            blDevices[blId].blKey = table.concat(strTab)

            debug(string.format('blKey: %s, blInternalId: %s', blDevices[blId].blKey, blDevices[blId].blInternalId),50)
        else
            debug('This device is probably offline - mac address: '..blId)
        end
    end
end

-- Get the temperature from a BroadLink device
-- returns true if the get status was successful
local function getTemperature(blId)
    local ok, payloadTab = sendReceive('Get temperature', makeSimpleMsg(blId, 0x10, plCmds.get), blId)
    if (not ok) then return ok end

    -- extract the msb temperature status from the payload
    local msb = payloadTab[plData.temperature.msb]
    -- For reasons completely unknown, the RM Pro randomly returns 0xf9 = 249 dec in the msb. We'll
    -- quard against this by considering any temperature that's over 70 deg C as being implausible.
    if (msb >= 70) then return false end
    local temperature = msb + payloadTab[plData.temperature.lsb]/10

    return ok, temperature
end

-- Get the energy from a BroadLink device
-- returns true if the get status was successful
local function getEnergy(blId)
    local ok, payloadTab = sendReceive('Get energy', makeGetEnergyMsg(blId), blId)
    if (not ok) then return ok end

    -- extract the energy status from the payload in Watt-hour (Wh)
    local energy = payloadTab[plData.energy.msb]*256 + payloadTab[plData.energy.isb] + payloadTab[plData.energy.lsb]/100

    return ok, energy
end

-- Get the relay status from a BroadLink device
-- returns true if the get status was successful
local function updateStatus(blId, lul_device, relay)
    local ok           = false
    local payloadTab   = {}
    local status       = 0
    local nightLight   = 0
    local blDeviceType = blDevices[blId].blDeviceType

    -- all devices are considered to be a single relay except the MP1 & SP1
    if (blDeviceType == 0x4ef7) then -- MP1 power strip with multiple relays
        -- 0x00 (off) or 0x01 (on) for each relay bit
        ok, payloadTab = sendReceive('Get status: MP1 relays', makeMP1StatusMsg(blId), blId)
        if (not ok) then return ok end

        -- extract the relay status for each relay
        local result = payloadTab[plData.status]
        -- mask off the unused upper bits, keeping bits 0-3
        local result = result % 2^4

        -- scan though the four relays looking for the one of interest. A bit library would be good.
        for n = 3, 0, -1 do
            local product = 2^n
            if (result >= product) then   -- bit is set
                if (relay == n+1) then status = 1 end
                result = result-product
            end
        end
    elseif (blDeviceType == 0x0000) then -- SP1 relay with no status feedback
    -- HACK elseif ((blDeviceType == 0x0000) or (blDeviceType == 0x2787)) then -- TESTING
        -- Do SP1s make their status available? - seems that they don't. So there is nothing to do.
        return true
    else -- single relay and maybe a night light: refer SP3
        ok, payloadTab = sendReceive('Get status: single relay', makeSimpleMsg(blId, 0x10, plCmds.get), blId)
        if (not ok) then return ok end

        local result = payloadTab[plData.status]
        -- mask off the unused upper bits, keeping bits 0-1
        result = result % 2^2
        if (result >= 2) then nightLight = 1 end  -- bit 1 is the night light
        result = result % 2^1
        if (result == 1) then status = 1 end      -- bit 0 is the power outlet
    end

    status = tostring(status)
    updateVariable('Status', status, SID.BINARY_LIGHT, lul_device)

    return ok
end

-- Scan the BroadLink device for a learnt IR code. Function needs to be global.
function scanningForBroadlinkIrCode(blId)
    m_IRScanCount = m_IRScanCount -1

    -- No msg rx'ed. Scanning failed to get a learnt code.
    if (m_IRScanCount <= 0) then m_PollEnable = m_PollLastState return end

    -- send the "have we got a learnt code" command
    local ok, payloadTab = sendReceive('Scanning for learnt code', makeSimpleMsg(blId, 0x10, plCmds.irGetCode), blId)

    -- Keep scanning if no message is Rx'ed or the returned errorMsg ~= '0000'. Note that the returned errorMsg
    -- can be '0xfff6', which appears to indicate that no IR code has been found so far: Refer to sendreceive()
    if (not ok) then
        -- check for a learnt IR code every 2 seconds for 2*12=24 seconds
        luup.call_delay('scanningForBroadlinkIrCode', SCAN_PERIOD, blId)
        return
    end

    -- Remove the payload header/prefix
    removePayloadHeader(payloadTab, blId)

    -- Got a learnt code. Extract the code from the payload
    local codeTab = {}
    for n = plData.irCodeIdx0, #payloadTab do table.insert(codeTab, string.format('%02x', payloadTab[n])) end

    updateVariable('LearntIRCode', table.concat(codeTab, ' '))

    -- restore the last polling state
    m_PollEnable = m_PollLastState
end

-- Start the scan for a learnt IR code
local function lookForLearntIrCode(blId)
    -- disable polling. Note this effects all Broadlink devices in use.
    m_PollLastState = m_PollEnable
    m_PollEnable = '0'

    updateVariable('LearntIRCode', 'No IR code was learnt')

    -- enter learning mode
    local ok, payloadTab = sendReceive('Start IR learn', makeSimpleMsg(blId, 0x10, plCmds.irLearnStart), blId)
    if (not ok) then m_PollEnable = m_PollLastState return end

    -- Note: the Broadlink RM PRO & RM Mini 3 automatically stop the IR learning mode after 30 seconds
    -- Check for a learnt IR code every 2 seconds for 2*12=24 seconds
    -- We can't scan any faster than the rx msg timeout - scan every 2 seconds
    m_IRScanCount = 12
    luup.call_delay('scanningForBroadlinkIrCode', SCAN_PERIOD, blId)
end

-- Start the scan for a learnt RF code. Function must be global.
function lookForLearntBroadlinkRfCode(blId)
    if (m_RfScanningState == RF.START_GET_FREQ) then
        -- Disable polling. Note this effects all Broadlink devices in use.
        m_PollLastState = m_PollEnable
        m_PollEnable = '0'

        -- initial situation
        updateVariable('LearntRFCode', 'No RF code was learnt')

        -- Enter RF frequency learning mode. The reply payload is just the TX'ed command echoed back, plus 15 0x00s to make up 16 bytes for AES.
        -- That is: 0x19 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        debug('Starting learning process',50)
        local ok, payloadTab = sendReceive('Start frequency learn', makeSimpleMsg(blId, 0x10, plCmds.rfStartGetFreq), blId)

        if (ok) then
            debug('Frequency learning has started: tap the button on the remote every second or so...',50)
            -- check for a learnt RF frequency every 2 seconds for 2*12=24 seconds
            m_RFScanCount = 12
            m_RfScanningState = RF.SCAN_FOR_FREQ
        else
            m_RfScanningState = RF.ABORT_1
        end

    elseif (m_RfScanningState == RF.SCAN_FOR_FREQ) then
        m_RFScanCount = m_RFScanCount-1

        -- Enter step 1 of RF learning. This checks the RF frequency. The reply is the TX'ed command
        -- echoed back, a found flag and 0x00s to make up 16 bytes for AES. Flag is at 0x04+1
        -- Not found: 0x1A 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        -- Found:     0x1A 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        -- Given up:  0x1A 0x00 0x00 0x00 0x04 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        debug('Scanning for frequency',50)
        local ok, payloadTab = sendReceive('Scanning for the remote\'s frequency', makeSimpleMsg(blId, 0x10, plCmds.rfScanForFreq), blId)

        if (ok and payloadTab and (payloadTab[plData.rfFoundFlag] == 0x01)) then
            debug('The remote\'s frequency has been found!',50)
            m_RfScanningState = RF.START_GET_CODE
        elseif (ok and payloadTab and (payloadTab[plData.rfFoundFlag] == 0x04)) then
            debug('Have given up on finding the remote\'s frequency - aborting',50)
            m_RfScanningState = RF.ABORT_2
        elseif (m_RFScanCount <= 0) then
            debug('Comms error finding the remote\'s frequency',50)
            m_RfScanningState = RF.ABORT_2
        end
        -- keep scanning if no message is Rx'ed

    elseif (m_RfScanningState == RF.START_GET_CODE) then
        -- Enter RF code learning mode.  The reply payload is just the TX'ed command echoed back,
        -- plus a Flag is at 0x04+1, plus 15 0x00s to make up 16 bytes for AES.
        -- That is: 0x1B 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        debug('Code learning has started: keep tapping the button on the remote every second or so...',50)
        local ok, payloadTab = sendReceive('Start code learn', makeSimpleMsg(blId, 0x10, plCmds.rfStartGetCode), blId)

        if (ok) then
            -- check for a learnt RF code every 2 seconds for 2*12=24 seconds
            m_RFScanCount = 12
            m_RfScanningState = RF.SCAN_FOR_CODE
        else
            m_RfScanningState = RF.ABORT_2
        end

    elseif (m_RfScanningState == RF.SCAN_FOR_CODE) then
        m_RFScanCount = m_RFScanCount-1

        -- Enter step 2 of RF learning. This checks for the RF code.
        -- The reply is either the error code 0xfff6 with no payload or the detected RF code.
        debug('Scanning for code',50)
        local ok, payloadTab = sendReceive('Scanning for the remote\'s code', makeSimpleMsg(blId, 0x10, plCmds.rfScanForCode), blId)

        if (ok and payloadTab) then
            debug('A remote code found! But will it work?',50)

            -- Got a learnt code. Extract the code from the payload.
            local codeTab = {}
            for n = plData.rfCodeIdx0, #payloadTab do table.insert(codeTab, string.format('%02x', payloadTab[n])) end

            updateVariable('LearntRFCode', table.concat(codeTab, ' '))

            m_RfScanningState = RF.DONE
        elseif (m_RFScanCount <= 0) then
            m_RfScanningState = RF.ABORT_2
        end

    elseif (m_RfScanningState == RF.DONE) then
        -- Scan complete. Stop the scanning. The reply payload is just the TX'ed command echoed back, plus 15 0x00s to make up 16 bytes for AES.
        -- That is: 0x1E 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00
        debug('Code learning has sucessfully finished',50)
        local ok, payloadTab = sendReceive('Stop RF learn', makeSimpleMsg(blId, 0x10, plCmds.rfLearnStop), blId)
        m_PollEnable = m_PollLastState
        return   -- success!!

    else
        debug('Error: unknown state - aborting',50)
        m_RfScanningState = RF.ABORT_1
    end

    -- did we fail to start the scan?
    if (m_RfScanningState == RF.ABORT_1) then
        debug('Error: comms error - aborting')
        m_PollEnable = m_PollLastState
        return
    end

    -- did something go wrong during the scan?
    if (m_RfScanningState == RF.ABORT_2) then
        -- No msg rx'ed. Scanning failed to get a learnt frequency or code.
        debug('RF code learning failed to get a frequency and/or code',50)
        local ok, payloadTab = sendReceive('Stop RF learn', makeSimpleMsg(blId, 0x10, plCmds.rfLearnStop), blId)
        m_PollEnable = m_PollLastState
        return
    end

    -- Note: the Broadlink RM PRO automatically stop the RF learning mode after about 23 seconds
    -- Check for a learnt IR code every 2 seconds for 2*12=24 seconds
    -- We can't scan any faster than the rx msg timeout - scan every 2 seconds
    luup.call_delay('lookForLearntBroadlinkRfCode', SCAN_PERIOD, blId)
end

-- Send IR & RF messages or learn IR or RF codes
local function ctrlrRf(blId, func, dataTab)
    if (not func) then return
    elseif (func == 1) then
        -- TX an IR or RF code
        local ok, payloadTab = sendReceive('Tx IR RF', makeTxIrRfMsg(blId, dataTab), blId)
    elseif (func == 2) then lookForLearntIrCode(blId)
    elseif (func == 3) then
        m_RfScanningState = RF.START_GET_FREQ
        lookForLearntBroadlinkRfCode(blId)
    else debug('Invalid function number') end
end

-- Send relay off/on message: SP1
-- returns true if the set was successful
local function SP1offOn(blId, lul_device, offOn)
    local ok = sendReceive('Relay off/on', makeSP1RelayMsg(blId, offOn), blId)
    -- Update the status for this device no matter what. With
    -- no status feedback, it's the best we can do.
    if (offOn) then
        updateVariable('Status', '1', SID.BINARY_LIGHT, lul_device)
    else
        updateVariable('Status', '0', SID.BINARY_LIGHT, lul_device)
    end
    return ok
end

-- Send relay off/on messageL SP2
-- returns true if the set was successful
local function SP2offOn(blId, lul_device, offOn)
    local ok = sendReceive('Relay off/on', makeSP2RelayMsg(blId, offOn), blId)
    if (ok) then ok = updateStatus(blId, lul_device) end
    return ok
end

-- Send relays (plural) off/on message: MP1
-- returns true if the set was successful
local function MP1offOn(blId, lul_device, offOn)
    local ok = false
    -- altId contains the relay number to use
    local altId = luup.devices[lul_device].id
    local _, _, relay = string.find(altId, 'rly(%d)')
    relay = tonumber(relay)
    if (relay) then
        ok = sendReceive('Relay off/on', makeMP1RelayMsg(blId, offOn, relay), blId)
        if (ok) then ok = updateStatus(blId, lul_device, relay) end
    end
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

-- Service: relay on/off
local function setTarget(lul_device, newTargetValue)
    local offOn = (tonumber(newTargetValue) == 1)
    local ok, blId, veraFunc = validatePtrs(lul_device)   -- function is SP1offOn(), SP2offOn() or MP1offOn()
    if (ok) then veraFunc(blId, lul_device, offOn) end
end

-- Service: send an IR pronto code or a Broadlink IR or Broadlink RF code
local function sendCode(lul_device, irRfCode)
    debug('Broadlink IR code 2 type = '..type(irRfCode))
    if (not irRfCode) then return end
    if (type(irRfCode) ~= 'string') then return end
    if (20 >= irRfCode:len()) then return end

    local ok, blId, veraFunc = validatePtrs(lul_device)   -- function is ctrlrRf(blId, 1, irCodeTab)
    if (not ok) then return end

    -- check for a base64 code
    local b64CodeTst = irRfCode:sub(1,1)
    -- test is case sensitive
    -- 26h --> 'J',   d7h --> '1',   b2h --> 's'
    if ((b64CodeTst == 'J') or (b64CodeTst == '1') or (b64CodeTst == 's')) then
       if (irRfCode:len() % 4 ~= 0) then debug('The base64 string length is not a multiple of four ',50) return end
       irRfCode = base64dec(irRfCode)
    end

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
    else debug('Invalid IR/RF code',50) return end

    -- for debugging purposes only
    if (DEBUG_MODE) then
        local irCodeTabHex = {}
        for _,v in ipairs(irCodeTab) do
            table.insert(irCodeTabHex, string.format('%02x', v))
        end
        debug('Broadlink IR code 2 = '..table.concat(irCodeTabHex,' '))
    end

    -- function 1 is send IR or RF code
    veraFunc(blId, 1, irCodeTab)
end

-- service: send a Pronto code
local function sendProntoCode(lul_device, ProntoCode)
    sendCode(lul_device, ProntoCode)
end

--[[
   service: send a Broadlink eControl code
   Sample input code:
     as an array:
     {-78,  6, 28, 0, 12, 14, 15, 26, 27, 15, 15, 26, 15, 26, 15, 26, 15, 26, 15, 26, 15, 26, 15, 27, 26, 15, 27, 15, 27, 0, 2, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

     as a string - commas optional:
     '-78,  6, 28, 0, 12, 14, 15, 26, 27, 15, 15, 26, 15, 26, 15, 26, 15, 26, 15, 26, 15, 26, 15, 27, 26, 15, 27, 15, 27, 0, 2, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0'

   Sample output result:
     'b2 06 1c 00 0c 0e 0f 1a 1b 0f 0f 1a 0f 1a 0f 1a 0f 1a 0f 1a 0f 1a 0f 1b 1a 0f 1b 0f 1b 00 02 5d 00 00 00 00 00 00 00 00 00 00 00 00'
]]
local function sendEControlCode(lul_device, eControlCode)
    if (type(eControlCode) == 'string') then
        local eControlCodeStr = eControlCode
        eControlCode = {}
        for code in eControlCodeStr:gmatch('%-?%d+') do table.insert(eControlCode, tonumber(code)) end
    end

    local hexTab = {}
    for _,v in ipairs(eControlCode) do
        -- Handle negative values: eg 433MHz leadin code is 0xb2 ie 178dec
        -- In the e-control json, it is -78dec. So 256+(-78) = 178dec = 0xb2
        if (v < 0) then v = 256 + v end
        table.insert(hexTab, string.format('%02x', v))
    end

    local irRfCode = table.concat(hexTab,' ')
    sendCode(lul_device, irRfCode)
end

-- Service: learn a Broadlink IR code
local function learnIRCode(lul_device)
    local ok, blId, veraFunc = validatePtrs(lul_device)   -- function is ctrlrRf(blId, 2)
    if (not ok) then return end

    -- function 2 is learn IR code
    veraFunc(blId, 2)
end

-- Service: learn a Broadlink RF code
local function learnRFCode(lul_device)
    local ok, blId, veraFunc = validatePtrs(lul_device)   -- function is ctrlrRf(blId, 3)
    if (not ok) then return end

    -- function 3 is learn RF code
    veraFunc(blId, 3)
end

-- Map BroadLink hex ids to friendly labels
-- https://github.com/mjg59/python-broadlink/blob/daebd806fd8529b9c29b4d70f82a036f30ea5847/broadlink/__init__.py#L18
local function setBlLabels()
--[[
   Possible other devices not yet described:
   RM Pro:  433 only with temp sensor:        blDeviceType 9863dec = 2687h
   RM Pro:  433 and 315 with no temp sensor:  blDeviceType 9885dec = 269dh
]]

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
    [0x7547] = {desc = 'SC1'                   },
    [0x4ef7] = {desc = 'MP1'                   },
    [0x2712] = {desc = 'RM2'                   },
    [0x2737] = {desc = 'RM Mini'               },
    [0x273d] = {desc = 'RM Pro Phicomm'        },
    [0x2783] = {desc = 'RM2 Home Plus'         },
    [0x277c] = {desc = 'RM2 Home Plus GDT'     },
    [0x272a] = {desc = 'RM2 Pro Plus'          },
    [0x2787] = {desc = 'RM2 Pro Plus 2'        },
    [0x278b] = {desc = 'RM2 Pro Plus BL'       },
    [0x279d] = {desc = 'RM3 Pro Plus'          },
    [0x278f] = {desc = 'RM Mini Shate'         },
    [0x2714] = {desc = 'A1'                    },
    [0x2722] = {desc = 'S1 SmartOne Alarm Kit' },
    [0x4e4d] = {desc = 'Dooya DT360E'          },

    -- added May 2020
    [0x27a9] = {desc = 'RM2 Pro Plus_300'      },
    [0x2797] = {desc = 'RM2 Pro Plus HYC'      },
    [0x4e4d] = {desc = 'RM2 Pro Plus R1'       },
    [0x4e4d] = {desc = 'RM2 Pro Plus PP'       },

    -- compliments of bblacey - thank you: devices with new leadin arrangements:
    [0x51da] = {desc = 'RM4 Mini'              },
    [0x5f36] = {desc = 'RM3 Mini'              },
    [0x6026] = {desc = 'RM4 Pro'               },
    [0x6070] = {desc = 'RM4 Mini'              },
    [0x610e] = {desc = 'RM4 Mini'              },
    [0x610f] = {desc = 'RM4 Mini'              },
    [0x61a2] = {desc = 'RM4 Pro'               },
    [0x62bc] = {desc = 'RM4 Mini'              },
    [0x62be] = {desc = 'RM4 Mini'              },

    -- April 2021
    [0x649b] = {desc = 'RM4 Pro'               },
    [0x653c] = {desc = 'RM4 Pro'               }
    }
end

-- Map BroadLink functionality to the functions that will do the actual work. Stick
-- all this stuff here, so we don't end up with forward references to the called functions
-- https://github.com/mjg59/python-broadlink/blob/daebd806fd8529b9c29b4d70f82a036f30ea5847/broadlink/__init__.py#L18
local function setDeviceConfiguration()
    setBlLabels()
    -- add in the empty devs arrays, then fill them in
    for k,_ in pairs(blDevs) do blDevs[k].devs = {} end

    local ptr = nil
    blDevs[0x0000].devs.rly1 = SP1offOn                        -- 'SP1'    has no status feedback?
    blDevs[0x2711].devs.rly1 = SP2offOn                        -- 'SP2'    SP2 & SP3 have energy sensors
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
    blDevs[0x7547].devs.rly1 = SP2offOn                        -- 'SC1'   has status feedback?
    ptr = blDevs[0x4ef7].devs                                  -- 'MP1'
        ptr.rly1 = MP1offOn                                    --
        ptr.rly2 = MP1offOn                                    --
        ptr.rly3 = MP1offOn                                    --
        ptr.rly4 = MP1offOn                                    --
    blDevs[0x2712].devs.ir = ctrlrRf                           -- 'RM2'
    blDevs[0x2737].devs.ir = ctrlrRf                           -- 'RM Mini'
    ptr = blDevs[0x273d].devs                                  -- 'RM Pro Phicomm'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x2783].devs                                  -- 'RM2 Home Plus'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x277c].devs                                  -- 'RM2 Home Plus GDT'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x272a].devs                                  -- 'RM2 Pro Plus'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x2787].devs                                  -- 'RM2 Pro Plus 2'
        ptr.ir    = ctrlrRf                                    --
        ptr.temp  = getTemperature                             --
        ptr.rf315 = ctrlrRf                                    --
        ptr.rf433 = ctrlrRf                                    --
        -- HACK ptr.rly1  = SP1offOn   -- HACK TESTING
    ptr = blDevs[0x278b].devs                                  -- 'RM2 Pro Plus BL'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x279d].devs                                  -- 'RM3 Pro Plus'
        ptr.ir    = ctrlrRf                                    --
        ptr.temp  = getTemperature                             --
        ptr.rf315 = ctrlrRf                                    --
        ptr.rf433 = ctrlrRf                                    --
    blDevs[0x278f].devs.ir = ctrlrRf                           -- 'RM Mini Shate'
    ptr = blDevs[0x2714].devs                                  -- 'A1'
        ptr.humidity   = nil                                   --
        ptr.lightLevel = nil                                   --
        ptr.noise      = nil                                   --
        ptr.temp       = nil                                   --
        ptr.voc        = nil                                   --
    ptr = blDevs[0x2722].devs                                  -- 'S1 SmartOne Alarm Kit'
        ptr.keyFob       = nil                                 -- Note: polling is too slow to make this item viable
        ptr.motionSensor = nil                                 -- Note: polling is too slow to make this item viable
        ptr.doorSensor   = nil                                 -- Note: polling is too slow to make this item viable
    ptr = blDevs[0x4e4d].devs                                  -- 'Dooya DT360E'
        -- add in whatever a 'Dooya DT360E' does here          --

    -- added May 2020: no idea what these do but will assume they can do IR & temp
    ptr = blDevs[0x27a9].devs                                  -- 'RM2 Pro Plus_300'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x2797].devs                                  -- 'RM2 Pro Plus HYC'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x4e4d].devs                                  -- 'RM2 Pro Plus R1'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    ptr = blDevs[0x4e4d].devs                                  -- 'RM2 Pro Plus PP'
        ptr.ir   = ctrlrRf                                     --
        ptr.temp = getTemperature                              --
    
    -- compliments of bblacey - thank you: devices with new leadin arrangements:
    blDevs[0x51da].devs.ir = ctrlrRf                           -- 'RM4b Mini'
    blDevs[0x51da].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x5f36].devs.ir = ctrlrRf                           -- 'RM3  Mini'
    blDevs[0x5f36].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x6026].devs.ir = ctrlrRf                           -- 'RM4 Pro'
    blDevs[0x6026].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x6070].devs.ir = ctrlrRf                           -- 'RM4 Pro'
    blDevs[0x6070].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x610e].devs.ir = ctrlrRf                           -- 'RM4? Mini'
    blDevs[0x610e].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x610f].devs.ir = ctrlrRf                           -- 'RM4c Mini'
    blDevs[0x610f].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x61a2].devs.ir = ctrlrRf                           -- 'RM4 Pro'
    blDevs[0x61a2].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x62bc].devs.ir = ctrlrRf                           -- 'RM4c Mini'
    blDevs[0x62bc].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x62be].devs.ir = ctrlrRf                           -- 'RM4c Mini'
    blDevs[0x62be].plHdrs  = {0x0004, 0x000d}                  --

    -- April 2021
    blDevs[0x649b].devs.ir = ctrlrRf                           -- 'RM4 Pro'
    blDevs[0x649b].plHdrs  = {0x0004, 0x000d}                  --
    blDevs[0x653c].devs.ir = ctrlrRf                           -- 'RM4 Pro'
    blDevs[0x653c].plHdrs  = {0x0004, 0x000d}                  --
--[[
    Other BroadLink devices:
    'TC2' Touch Control: 1 to 3 gang switches; is a slave device and is typically controlled by a 'RM Pro +' using 433 MHz
]]
end

-- Go through all the BroadLink devices and build up a table of the children they will use
local function setVeraDevices()
    for blId, blDevice in pairs(blDevices) do
        local mac   = blId
        local BLink = blDevice.blDesc..' - '
        local altId, veraDesc, dev, file = '', '', '', ''

        -- get the info for all the children this BroadLink device will need
        for k, v in pairs(blDevs[blDevice.blDeviceType].devs) do
            altId = mac..'_'..k
            debug('k = '..k)
            -- get the function for this vera device
            func = v
            -- ready for relays
            dev, file = DEV.BINARY_LIGHT, FILE.BINARY_LIGHT
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
--            elseif (k=='rf315') then
--                veraDesc = BLink..'RF 315 1'
--                dev, file = DEV.IR_TRANSMITTER, FILE.IR_TRANSMITTER
--            elseif (k=='rf433') then
--                veraDesc = BLink..'RF 433 1'
--                dev, file = DEV.IR_TRANSMITTER, FILE.IR_TRANSMITTER
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
                    blId       = mac,     -- we use the BroadLink device mac address to identify the child's parent hardware
                    veraDesc   = veraDesc,
                    veraDevice = dev,
                    veraFile   = file,
                    veraFunc   = func
                 -- veraId is set up once the child is created
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
end

-- Poll the BroadLink device for data. Function needs to be global.
function pollBroadLinkDevices()
    if (m_PollEnable ~= '1') then return end

    -- poll sensors: temperature, humidity, etc contained in all the discovered BroadLink devices
    -- altId (that is k) is of the form: 'xx:xx:xx:xx:xx:xx_temp' where the xxs make up the mac address
    for k,v in pairs(veraDevices) do
        local blId       = v.blId
        local veraId     = v.veraId
        local veraDevice = v.veraDevice
        local veraFunc   = v.veraFunc   -- look up the function to be used for this device

        -- make sure we have a BroadLink device and an associated function and then go poll all the sensors found
        if (blId and veraFunc and veraDevice) then
            if     (veraDevice == DEV.DOOR_SENSOR)        then updateVariable('Tripped',      veraFunc(blId), SID.DOOR_SENSOR,     veraId)
            elseif (veraDevice == DEV.GENERIC_SENSOR)     then updateVariable('CurrentLevel', veraFunc(blId), SID.GENERIC_SENSOR,  veraId)
            elseif (veraDevice == DEV.HUMIDITY_SENSOR)    then updateVariable('CurrentLevel', veraFunc(blId), SID.HUMIDITY_SENSOR, veraId)
            elseif (veraDevice == DEV.LIGHT_SENSOR)       then updateVariable('CurrentLevel', veraFunc(blId), SID.LIGHT_SENSOR,    veraId)
            elseif (veraDevice == DEV.MOTION_SENSOR)      then updateVariable('Tripped',      veraFunc(blId), SID.MOTION_SENSOR,   veraId)
            elseif (veraDevice == DEV.SMOKE_SENSOR)       then updateVariable('Tripped',      veraFunc(blId), SID.SMOKE_SENSOR,    veraId)
            elseif (veraDevice == DEV.TEMPERATURE_SENSOR) then

                -- This is a pretty crude correction and is only likely to be close to accurate at one particular
                -- temperature. Get the temperature and temperature correction factor and update the result.
                local offsetStr = luup.variable_get(SID.TEMPERATURE_SENSOR, 'TemperatureOffset', veraId)
                local temperatureOffset = tonumber(offsetStr)
                if not temperatureOffset then temperatureOffset = 0 end
                local ok, temperature = veraFunc(blId)
                if (ok) then
                    updateVariable('CurrentTemperature', temperature + temperatureOffset, SID.TEMPERATURE_SENSOR, veraId)
                else
                    debug(v.veraDesc..': failed to get temperature. Is the device offline?',2)
                end

            -- add in more sensors here with additional elseif

            else -- update the status of any relays
                -- altId (that is k) contains the relay number to use (if any)
                local _, _, relay = string.find(k, 'rly(%d)')
                relay = tonumber(relay)
                if (relay) then
                    updateStatus(blId, veraId, relay)
                else
                    debug(v.veraDesc..': device is not a sensor or if a sensor; is not coded for')
                    debug(string.format('%s: veraId: %d, blId: %s, altId: %s', v.veraDesc, veraId, blId, k))
                    debug(v.veraDesc..': '..veraDevice)
                end
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
    debug('Using: '.._VERSION)   -- returns the string: 'Lua x.y'

    -- set up some defaults:
    updateVariable('PluginVersion', PLUGIN_VERSION)

    -- set up some defaults:
    local debugEnabled = luup.variable_get(PLUGIN_SID, 'DebugEnabled', THIS_LUL_DEVICE)
    if not((debugEnabled == '0') or (debugEnabled == '1')) then
        debugEnabled = '0'
        updateVariable('DebugEnabled', debugEnabled)
    end
    DEBUG_MODE = (debugEnabled == '1')

    local pluginEnabled = luup.variable_get(PLUGIN_SID, 'PluginEnabled', THIS_LUL_DEVICE)
    if not((pluginEnabled == '0') or (pluginEnabled == '1')) then
        pluginEnabled = '1'
        updateVariable('PluginEnabled', pluginEnabled)
    end
    if (pluginEnabled ~= '1') then return true, 'All OK', PLUGIN_NAME end

    m_json = loadJsonModule()
    if (not m_json) then return false, 'No JSON module found', PLUGIN_NAME end

    local broadLinkDevices = luup.variable_get(PLUGIN_SID, 'BroadLinkDevices', THIS_LUL_DEVICE)
    if ((broadLinkDevices == nil) or (broadLinkDevices == '')) then
        broadLinkDevices = '{}'
        updateVariable('BroadLinkDevices', broadLinkDevices)
    end

    local pollEnable = luup.variable_get(PLUGIN_SID, 'PollEnable', THIS_LUL_DEVICE)
    if not((pollEnable == '0') or (pollEnable == '1')) then
        -- turn the polling on
        m_PollEnable = '1'
        polling(m_PollEnable)
    else
        m_PollEnable = pollEnable
    end

    -- don't allow polling any faster than five minutes
    local pollInterval = luup.variable_get(PLUGIN_SID, 'PollInterval', THIS_LUL_DEVICE)
    local theInterval = tonumber(pollInterval)
    if ((theInterval == nil) or (theInterval < FIVE_MIN_IN_SECS)) then
        m_PollInterval = FIVE_MIN_IN_SECS
        updateVariable('PollInterval', tostring(FIVE_MIN_IN_SECS))
    else
        m_PollInterval = theInterval
    end

    -- Works ok but is not called any where; testing only
    -- However it would be called like this, in this sort of framework.
    -- sendPairingMsg()

    setDeviceConfiguration()
    OUR_IP = getOurIPaddress()

    -- We need the history of past online devices. If a device goes offline temporarily, it
    -- will still be possible to retain its children during the append process further below.
    blDevices = m_json.decode(broadLinkDevices)
    if (not blDevices) then debug('JSON decode error: blDevices is nil') blDevices = {} end

    -- What's out there? Build and/or update the blDevices table.
    broadcastDiscoverDevicesMsg()

    -- Now that all the BroadLink devices that are actually online have been
    -- discovered, we can go get their authorisation info: blKey & blInternalId
    -- Offline devices will just time out and be logged as such.
    getAuthorisation()

    -- go through all the BroadLink devices and build up a table of the children they will use
    setVeraDevices()

    -- Note that only the online devices get updated. Offline devices rely on the previous online history loaded
    -- from the persistent json varaible. This also updates blKey & blInternalId discovered during authorisation.
    updateVariable('BroadLinkDevices', m_json.encode(blDevices))

    -- make a child for each device found as part of each BroadLink device
    local child_devices = luup.chdev.start(THIS_LUL_DEVICE)

--[[
    Add child devices:

    The child D_*.xml files each specify a "serviceList" with a link to the associated S_*.xml file containing
    the actionList. With the parent "handleChildren" set to one, the child serviceList is handled by the parent.
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
        https://community.getvera.com/t/plugin-and-childs/189244/6
        https://community.getvera.com/t/variables-scope-and-visibility/164611/10
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

    -- if any of the children specified above are brand new, changed or deleted, then this code will result in a Luup engine restart
    luup.chdev.sync(THIS_LUL_DEVICE, child_devices)

    -- find all of the children of this parent device
    -- and then for each child record its Vera id
    -- if a device is off line, blDevices contains sufficient information to keep the children in place
    for deviceID,v in pairs(luup.devices) do
        if (v.device_num_parent == THIS_LUL_DEVICE) then
            -- for each vera child device we record its vera id
            -- where v.id is the altId used to index our children
            veraDevices[v.id].veraId = deviceID
            -- The user may have changed the original Vera device description as seen in the UI.
            -- So keep track of any users changes to the device descriptions.
            veraDevices[v.id].veraDesc = v.description

            -- for temperature devices, we'll provide a very crude temperature correction facility
            if (veraDevices[v.id].veraDevice == DEV.TEMPERATURE_SENSOR) then
                local temperatureOffset = luup.variable_get(SID.TEMPERATURE_SENSOR, 'TemperatureOffset', deviceID)
                if ((temperatureOffset == nil) or (temperatureOffset == '')) then
                    updateVariable('TemperatureOffset', '0', SID.TEMPERATURE_SENSOR, deviceID)
                end
            end
        end
    end

    -- delay so that the first poll occurs delay interval after start up
    local INITIAL_POLL_INTERVAL_SECS = 85
    luup.call_delay('pollBroadLinkDevices', INITIAL_POLL_INTERVAL_SECS)

    -- required for UI7. UI5 uses true or false for the passed parameter.
    -- UI7 uses 0 or 1 or 2 for the parameter. This works for both UI5 and UI7
    luup.set_failure(false)

    return true, 'All OK', PLUGIN_NAME
end

