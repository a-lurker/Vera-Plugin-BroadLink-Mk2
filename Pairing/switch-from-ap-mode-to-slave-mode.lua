-- a-lurker, copyright 2024
-- First release 27 April 2024; updated April 2024

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
    The BroadLink device may have been already configured via a mobile phone. We need
    to change the mode back to AP mode. Place the BroadLink device into AP mode by holding
    down the reset button for about four seconds. A successful change to AP mode is indicated
    by the blue LED: four flashes followed by a one second pause.

    At this point the device acts as WiFi access point (AP). It runs a DCHP server on 192.168.10.1
    Any Vera, PC, etc, that connects to the AP, will be given an address of 192.168.10.2, which will
    increment, as further devices are connected to the AP.

    We need to send a pairing message to the AP on 192.168.10.1 In this pairing message, we send
    the WiFi SSID and password of the AP that is part of our Vera/openLuup network. Once successfully
    received, the BroadLink device with disable its own AP and DCHP server and connect to the AP
    specified in our message ie the LAN connected to Vera/openLuup. The blue LED goes completely off.
    The BroadLink device effectively stops acting as an AP and changes to being a slave device.
    At this point we can start to use the facilities the BroadLink device offers.

    Note: this code has been extracted from the plugin, so it contains
    some irrelevant and unused sections of code. eg blId is always nil.

    Refs:
       https://github.com/mjg59/python-broadlink
       https://github.com/lprhodes/broadlinkjs-rm/blob/master/index.js
       https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1
       https://github.com/sayzard/BroadLinkESP/blob/master/BroadLinkESP.cpp
       https://github.com/mob41/broadlink-java-api/tree/master/src/main/java/com/github/mob41/blapi
]]
--[[
    Place the SSID and password as arguments to the command line:

    Typical output to command:

    Initialising pairing
    Using: Lua 5.1
    AppVersion: 0.5

    Using: SSID = abc and password = xyz

    Switching BroadLink AP to slave mode
    Sending "Pairing" message. txMsg length = 136
    Pairing completed OK!
]]

local APP_VERSION     = 0.50
local BROADLINK_AP_IP = '192.168.10.1'
local UDP_IP_PORT     = 80
local MSG_TIMEOUT     = 1

local SSID = 'my_SSID'
local PASS = 'my_PASS'

local CHECKSUM_SEED = 0xbeaf

local m_doEncodeDecode = true  -- used for testing purposes only

local socket = require('socket')

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

local DEBUG_MODE = false

local function debug(s, debugLevel)
    if (debugLevel == 50) then
        print(s)
    elseif DEBUG_MODE then
        print(s)
    end
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

-- Table creation for messages
local function makeEmptyTable(length)
    local zeroTab = {}
    -- set the table to all nulls
    for i = 1, length do zeroTab[i] = 0x00 end
    return zeroTab
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

-- unused but keeps the interpreter happy
local function encryptDecrypt()
end

-- Note: this code has been extracted from the plugin, so it contains
-- some irrelevant and unused sections of code. eg blId is always nil.
-- Master send and receive with decrypted payload extraction
local function sendReceive(msgType, txMsgTab, blId)
    local ok = true
    local pairing = false
    local ipAddress = ''
    local key = nil

    if (blId == nil) then
        -- we don't have an ID for the device until the device is paired
        pairing = true
        ipAddress = BROADLINK_AP_IP
    else -- known device
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
    if (txMsgLen ~= #txMsgTab) then debug('Error: not all the table elements are a single byte long') end

    local udp = socket.udp()
    udp:settimeout(MSG_TIMEOUT)

    -- Doco says the first sendto will do this automatically.
    -- However that seems not to be always the case.
    udp:setsockname("*",0)

    -- Don't show WiFi details.
    local above = ' as shown above'
    if (pairing) then above = '' end
    debug('Sending "'..msgType..'" message'..above..'. txMsg length is '..txMsgLen,50)

    -- Note: the maximum datagram size for UDP is (potentially) 576 bytes
    local resultTX, errorMsg = udp:sendto(txMsg, ipAddress, UDP_IP_PORT)

    if (resultTX == nil) then
        debug('TX of "'..msgType..'" msg to '..ipAddress..' failed: '..errorMsg)
        udp:close()
        return false
    end

    -- Note: aircon codes can be very long. Buffer overruns of rx'ed messages will throw a checksum error.
    local rxMsg, ipOrErrorMsg = udp:receivefrom()
    udp:close()

    if (rxMsg == nil) then
        debug('RX of response to "'..msgType..'" msg from '..ipAddress..' failed: '..ipOrErrorMsg)
        return false
    end

    -- convert the rx'ed msg to a byte table - we like tables
    local rxMsgTab = {}
    for c in rxMsg:gmatch('.') do table.insert(rxMsgTab, string.byte(c)) end
    local rxMsgLen = #rxMsg

    local deviceType = string.format('%02x%02x', rxMsgTab[0x25+1], rxMsgTab[0x24+1])
    local replyToCmd = string.format('%02x%02x', rxMsgTab[0x27+1], rxMsgTab[0x26+1])
    debug('Broadlink device type "'..deviceType..'" replied with '..replyToCmd)

    if (rxMsgTab[0x26+1] == blCmds.pairing.rx) then
       debug('Response to "Pairing" command received sucessfully!',50)
    end

    -- have a look at the error information returned
    -- 0xfffb means???
    -- 0xfff9 means an error of some sort. Seems to occur if the WiFi signal is marginal. The payload will be nil.
    -- 0xfff6 is returned when no IR/RF code has been learnt? The payload will be nil.
    local errorMsg = string.format('%02x%02x', rxMsgTab[0x23+1], rxMsgTab[0x22+1])
    if (errorMsg ~= '0000') then
       debug('Error: errorMsg = '..errorMsg,50)
       ok = false
    end
    -- HACK if ((errorMsg ~= '0000') and (errorMsg ~= 'fff6')) then debug('Error: errorMsg = '..errorMsg,50) return ok end

    -- pairing result doesn't have a checksum
    if ((not pairing) and (not validChecksum(rxMsgTab))) then
        debug('Error: checksum of received msg is incorrect')
        ok = false
    end

    -- get the received header ready just for debugging
    local headerTab = {}
    for i=1, 0x37+1 do headerTab[i] = rxMsgTab[i] end

    -- now get the received payload starting at 56d=0x38 (zero based count as per the references)
    local rxedPayloadTab = {}
    for i = 0x38+1, rxMsgLen do table.insert(rxedPayloadTab, rxMsgTab[i]) end
    if (#rxedPayloadTab == 0) then
        debug('Received response to "'..msgType..'" msg is shown below. rxMsg length is '..tostring(rxMsgLen))
        tableDump('No payload found. Header follows:', headerTab)
        return false
    end

    -- decrypt the payload
    -- The "pairing" message doesn't encrypt/decrypt, so the key will be nil on that occasion.
    -- Before authorisation is completed, the key will equal the "initialKey".
    -- After authorisation it will be the key supplied by the discovery process.
    local payloadTab = {}

    if (pairing) then -- not encrypted
        payloadTab = rxedPayloadTab
    elseif (m_doEncodeDecode) then -- m_doEncodeDecode used for testing purposes only
        payloadTab = encryptDecrypt(key, rxedPayloadTab, false)
    else  -- don't decode (testing only)
        payloadTab = rxedPayloadTab
    end

    -- pairing result doesn't have a checksum
    if ((not pairing) and (#payloadTab > 0) and (not validPayloadChecksum(rxMsgTab, payloadTab))) then
        debug('Error: checksum of received payload is incorrect')
        ok = false
    end

    -- show the full received message. ie header and decrypted payload
    tableDump('Received response to "'..msgType..'" msg as shown below. rxMsg length is '..tostring(rxMsgLen)..' Decrypted received header follows:',  headerTab)
    tableDump('Decrypted received payload follows:', payloadTab)

    return ok, payloadTab
end

--[[
    The "pairing" message will be sent to the "BroadLinkProv" AP
    Once sucessfully received, the BroadLink device deletes its
    AP function and changes to a slave, connected to our LAN.
    That's assuming the correct SSID and PASS were made use of.
    The tx'ed msg carrys no payload.
    https://github.com/mjg59/python-broadlink/blob/daebd806fd8529b9c29b4d70f82a036f30ea5847/broadlink/__init__.py#L1077

    Note: that the pairing msg contains no payload.
    Note: the response to the pairing msg contains no checksum
]]
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

--[[
    BroadLink use at least a couple of AP SSID names: ie "BroadLinkProv" and "BroadLink_WiFi_Device"

    Right from the start, you should be able to detect the AP with:   ping -c 5  192.168.10.1

    This function sends the "pairing" message to the BroadLink AP. Returns true if the pairing was successful.

    NOTE: for this to work; connect a laptop or PC to the AP SSID. Then run this code.
]]
local function sendPairingMsg()
    -- Use the factory default BroadLink WiFi access point ip address.
    -- Note that the pairing msg contains no payload.
    -- Note the response contains no checksums
    local ok = sendReceive('Pairing', makePairingMsg())
    if (ok) then
        debug('Pairing completed OK!',50)
    else
        debug('Pairing failed',50)
    end
end

local function luaStartUp()
    debug('\nInitialising pairing',50)

    debug('Using: '.._VERSION,50)   -- returns the string: 'Lua x.y'

    -- set up some defaults:
    debug('AppVersion: '..APP_VERSION,50)

    -- debug('Executable path: '   ..arg[-1],50)
    -- debug('Script path & name: '..arg[ 0],50)

    if (arg[1] and arg[2]) then
        SSID = arg[1]
        PASS = arg[2]
        debug('\nUsing: SSID = '..SSID..' and password = '..PASS..'\n',50)
        debug('Switching BroadLink AP to slave mode',50)
        sendPairingMsg()
    else
        debug('\nUsage: switch-from-ap-mode-to-slave-mode SSID password',50)
    end
end

luaStartUp()

