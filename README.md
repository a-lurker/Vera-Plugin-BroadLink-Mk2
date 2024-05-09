# <img align="left" src="https://a-lurker.github.io/icons/BroadLink_50_50.png"> Vera-Plugin-BroadLink-Mk2

Connect openLuup or Vera to miscellaneous BroadLink devices.

This plugin is based on information from here:

https://github.com/mjg59/python-broadlink
https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1
https://github.com/sayzard/BroadLinkESP/blob/master/BroadLinkESP.cpp

## Plugin installation
You can install the plugin from the openLuup or Vera `Alternate App Store`, which works together with the `AltUI` plugin. The AltApp plugin integrates with and extends AltUI by becoming a menu item in that UI:

ie AltUI → More → App Store

The store might not work on Vera 3 because of problems along the lines of using secure URLs. (https)

In that case it can be installed manually:
1. Download the files from GitHub
2. Upload them to Vera: apps→develop apps→luup files→upload
3. Create a device: apps→develop apps→create device & fill in these two fields:
   - Upnp Device Filename: D_BroadLink_Mk2_1.xml
   - Upnp Implementation Filename: I_BroadLink_Mk2_1.xml
   - leave the rest blank
4. Restart luup: apps→develop apps→Test Luup code and run the code
```lua
luup.reload()
```
5. You should find the new device in 'No Room'. Depending on the parent device model, eg `RM4 Mini S`, you will also find any child devices, such as  temperature and humidity. A couple of restarts of openLuup will be required.

## BroadLink device is in Access Point (AP) mode
The device is in Access Point (AP) mode when purchased.

- AP mode: The LED flashes fairly rapidly and inserts a small pause before flashing again.
- Slave/paired mode: The LED only flashes when a code is sent.

Typically a user would find the device in the BroadLink app and go from there. However the are two options:

1. Connect to the device with the BroadLink app and `get the codes you want` from the BroadLink cloud connection. Since about 2020 BroadLink devices will `not respond locally` if they have been linked to the BroadLink cloud via the BroadLink app. To use the plugin from this point, you have to delete the device in the app and then do a factory reset of the device to get it back into AP mode. Just hold the small button down for about four seconds.

2. Easier alternative: after purchase, don't make use of the app and immediately switch the device from AP mode to slave mode.

## Switching from AP mode to slave/paired mode
You need to switch the device from AP mode to slave mode, so the plugin can be used. There are couple of ways this can be done:

1. Use any other convenient computer to connect to the BroadLink device, while it's in AP mode. Then on that computer, execute the [switch-from-ap-mode-to-slave-mode.lua](https://github.com/a-lurker/Vera-Plugin-BroadLink-Mk2/tree/master/Pairing) script to place the BroadLink device into slave mode.

    A Lua interpreter needs to be installed on the computer linked to the access point. eg for a PC, see [Lua for windows](https://github.com/rjpcomputing/luaforwindows).

    Execute the script, keeping in mind the paths to the script, etc.

```bash
lua switch-from-ap-mode-to-slave-mode MySSID MyWifiPassword
```

2. If you have the [BroadLink comand line interface](https://github.com/mjg59/python-broadlink/blob/master/cli/README.md) program already installed, you can instruct the device to exit AP mode and join your network via the specified WiFi connection.
```bash
broadlink_cli --joinwifi MySSID MyWifiPassword
```

## Discovery
Once in slave mode the BroadLink device LED should stop flashing and after a short while the device will be pingable (find its IP on your router e.g.)

```bash
ping -c 5 BroadLink_IP_address
```
The plugin will discover any BroadLink devices connectd to the same LAN.

BroadLink comand line interface users (broadlink_cli) will need to invoke the `broadlink_discovery` program. They can then do, for example, call up the sensors by inserting the device's IP address & MAC address:
```bash
python-broadlink/cli/broadlink_cli --device "0x2737 168.20.2.3 24ea3223f73e" --sensors
```

## Caveats
If the device is on a different subnet the pairing process will fail.

Keep in mind that since about 2020, BroadLink has evolved the protocol and once a device is paired with the cloud, it no longer accepts local network requests. Users have to remove the BroadLink device from their cloud account using the BroadLink App.

The plugin has only been tested on the RM3 Pro 2, RM Mini & RM4 Mini S devices. Other users have had success with other models. While other devices may be discovered, they might not work. The log reports the "Hexadecimal IDs" of devices it does not recognise. Many of the devices work in the same manner, so it may only need to have the "Hexadecimal ID" added to the list of known devices.

## IR codes
If the LED on your device flashes when you transmit an IR code, the plugin is working. It's a different matter whether you have the correct code or not.

Many learnt codes have excessive replication and some codes are not replicated enough. ie some TVs, etc require a code to be sent two or three time in close succession, for them to work.

RC5, RC6 and MCE codes use a toggle bit, which cause havoc with learnt codes. The [Virtual Pronto Remote plugin](https://github.com/a-lurker/Vera-Plugin-Virtual-Pronto-Remote)  can handle these in conjunction with this BroadLink plugin.

For codes refer to [Remote Central](https://www.remotecentral.com).

## Logging
Logging can be enabled by setting the DebugEnabled flag to '1'. You can use AltUI plugin with Vera to look at the log file:

See Misc→OS Command→Tail Logs Tab

Note: you can change the 50 to say 500 to see more log info.

In openLuup use the console logs:

http://<openLuup_ip_address>:3480/console?page=log

Or use the [Vera only Infoviewer plugin](https://github.com/a-lurker/Vera-Plugin-Info-Viewer). Please provide a log file with any bug reports, otherwise queries may not be responded to.

## Functionality
### What the plugin will do:
- Econtrol, BroadLink and ProntoCodes can be used.

- The one instance of the plugin can (in theory) handle multiple BroadLink physical devices. The plugin will produce child devices as necessary, based on the capabilities of each BroadLink device discovered. eg a BroadLink "RM4 Mini S" will have IR, temperature and humidity child devices associated with it.

- BroadLink WiFi operated switches such as the SP1 & SP2 & SC1 should work but the MP1 may need work - haven't been able to test this.

### What the plugin will not do:
- Wall switches operated locally will provide on/off status but the update period in the UI will be long (minutes) ie not instant status

- The plugin does not interact with the "e-Control" phone app in any way. However e-control codes can be used by the plugin.

- The plugin parent doesn't store IR or RF codes. Codes need to be sent by the IR child.

## Potential problems:
- RF codes may or may not work. Especially rolling codes.

- Getting codes:  Apparently you can download Econtrol codes held by the "e-Control" app. Google for how this is done.

- Your router blocks UDP broadcast traffic - that will cause problems - read your router manual.

- The BroadLink devices are identified by their MAC addresses. If you change the IP address of a BroadLink device for any reason, you need to restart the Luup engine. The new ip address will be discovered and used.

- After a openLuup engine restart, there is 85 second delay before the plugin starts polling. It then polls at a minimum of every five minutes. So temperatures, etc are updated at this rate.

- Some BroadLink devices can control remote devices on 315 MHz, as well as 433 MHz. Some just allow 433 MHz (country based). The box the unit is delivered in, says what it contains. I'm unsure how this can be detected programmatically.


## Usage
Codes can be cut & pasted into the actions below and tried out in one of the AltUI/Console Lua test boxes. Try not to confuse the usage of the parent and child devices.

Sending a Econtrol code:
```lua
local deviceID = 162

-- You can pass the code as an array or as a string. Use curly braces/braclets
-- or a quoted string. Using an array here.
local rfCode = {-78,  6, 28, 0, 12, 14, 15, 26, 27, 15, 15, 26, 15, 26, 15, 26, 15, 26, 15, 26, 15, 26, 15, 27, 26, 15, 27, 15, 27, 0, 2, 93, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

luup.call_action('urn:a-lurker-com:serviceId:IrTransmitter1', 'SendEControlCode', {eControlCode = rfCode}, deviceID)

return true
```

Sending a Pronto Code:
```lua
local deviceID = 164
local prontoCode = '0000 0067 0000 0010 0060 0018 0018 0018 0030 0018 0018 0018 0018 0018 0030 0018 0018 0018 0018 0018 0018 0018 0018 0018 0018 0018 0018 0018 0030 0018 0030 0018 0018 0018 0018 037E'

luup.call_action('urn:a-lurker-com:serviceId:IrTransmitter1', 'SendProntoCode', {ProntoCode = prontoCode}, deviceID)

return true
```

Sending a BroadLink IR or RF code:
```lua
local deviceID = 162
local rfCode = 'b2 06 1c 00 0c 0e 0f 1a 1b 0f 0f 1a 0f 1a 0f 1a 0f 1a 0f 1a 0f 1a 0f 1b 1a 0f 1b 0f 1b 00 02 5d 00 00 00 00 00 00 00 00 00 00 00 00'

luup.call_action('urn:a-lurker-com:serviceId:IrTransmitter1', 'SendCode', {Code = rfCode}, deviceID)

return true
```

[Base64 codes](https://github.com/smartHomeHub/SmartIR/commit/7ff179adc3128cad2d545606188a4b1fec04660e) can be sent. The usage of a Base64 code is automatically detected.

Sending a `BroadLink Base64` IR code for a [Daikin Aircon](https://github.com/smartHomeHub/SmartIR/commit/7ff179adc3128cad2d545606188a4b1fec04660e#diff-29efd5a3b467d774e6f57142e5613bc4607778986136d90a40da0f8d0f49ffaeR29) - set temperature to 21 degrees.
```lua
local deviceID = 162

local base64Code = 'JgBMAnA6DisOKw0PDRAMEA0sDQ8NEA0sDSsPDg0sDQ8NEA4rDSsNEA8qDSwNDw8ODSwNDw0QDSsNEQ0PDQ8NEA4ODg8NDw4PDQ8ODw0PDRANDw0QDQ8NEA0QDBAODw0QDCwNEA4ODRANDw4PDisNKw4PDRANDw0sDQ8OKw0QDRAMEA0PDRANDw4rDSwNDw4rDSwNDw0QDisNDw0sDSwNDw4QDCwMEA4PDCwPDg0sDSsOKw0sDQ8NEA0PDhAMEAwQDRANDw0QDRAODg4PDREMDw0QDQ8NEA0PDREMDw4PDBANEA0PDRANDw0QDQ8NEA0QDBAODw0PDRANDw0QDRAMEA0QDQ8ODwwQDRAMEA0QDBANEAwQDRANLAwsDisOKw0PDg8NKw4PDQACMnQ6DisNLA0PDRANDw4rDg8MEA0sDSwNDwwtDRAMEA0sDSwMEA0sDisNDw4PDioNEA4ODisODg8ODhANDg4PDg4ODw4PDBANDw0QDRAPDQ0QDRANDw0QDQ8ODw0PDSwNEA0PDRAMEA0QDSsNLA4PDQ8NEA0rDg8OKg0QDw4NEA0PDRANDw0sDSwODg4rDSwMEA0QDSwMEA0sDisMEA0QDSwNEA0PDCwNEA0rDSwNLA4rDg4ODw0PDRANDw0QDg4NEQ0ODRANDw0QDRANDw8ODg8MEA0QDQ8NEA0PDRAODg0QDQ8NEA0PDRANEAwQDRANEAwQDQ8PDw0PDRAMEA0QDg4NEA0PDg8NDw4PDBANEA0PDRAOKg8qDSwNLA0PDRAOKwwQDgANBQwsDisOKw0PDg8NKw=='

luup.call_action('urn:a-lurker-com:serviceId:IrTransmitter1', 'SendCode', {Code = base64Code}, deviceID)

return true
```

## Learning codes
The plugin can learn IR & RF codes. It works pretty well for IR codes but is a bit suspect when learning RF codes. To start the learning process issue these commands to the appropriate `child device`, not the parent device:

```lua
-- learn IR code
luup.call_action('urn:a-lurker-com:serviceId:IrTransmitter1', 'LearnIRCode', {}, deviceID)
```

```lua
-- learn RF code
luup.call_action('urn:a-lurker-com:serviceId:IrTransmitter1', 'LearnRFCode', {}, deviceID)
```

The LED will light up on the BroadLink device and you have about 30 seconds to learn the code. For IR codes just tap the remote button. For RF codes it's more complicated. Once learning starts hold the remote button down for about four seconds (this gets the frequency). Wait a second and then tap the remote button (this gets the code). This sequence is not easy to do and codes may not be learnt or may be incorrect.

The `parent device`, not the child device, reports the learnt codes in "LearntIRCode" and "LearntRFCode" variables as seen under the variables tab. If a code is not learnt then the variable reports "No IR code was learnt", ditto for RF codes.

Note: a JSON module is required to be available to the plugin. More than likely the plugin will find one. If one is not found, you will be notified in the UI top banner at Luup engine start up. Refer to this post for a [suitable module](https://a-lurker.github.io/docs/#/openluup-and-json).

## Calibration
Measured temperatures can have an offset applied. It's a crude approach to correction but may help those interested. In general expecting sub one degree Centigrade accuracy (or even two degrees) from the BroadLink devices is probably overly optimistic.

## Deleting devices
Problem:
I delete them, but in time they reappear.

Answer:
Delete the contents of the variable "BroadLinkDevices", Save and then restart the Luup Engine. After that takes effect (can take a few minutes), restart your browser. Basically the plugin still thinks you have the old devices installed and needs to be told they are gone.

Alternatively you can edit the device out of the json found in the `BroadLinkDevices` variable.
