# Wireshark Decoder Plugin - B3 Entrypoint FIXP Protocol - Simple Binary Encoding (SBE)
This Wireshark plugin allows you to decode SBE (Simple Binary Encoding) messages from the B3 binary order entry gateway. 
It provides a convenient way to analyze and interpret the network traffic between the B3 binary gateway and your application.

## Features
- Decodes SBE messages transmitted over the network.
- Displays decoded message fields in a human-readable format.
- Supports both inbound and outbound messages.
- Provides detailed information about each message field.
- Makes it easy to analyze and troubleshoot network communication.

## Installation
1. Download the plugin `plugins/<version>/b3.entrypoint.sbe.wireshark.plugin.lua`
2. Copy the plugin binary to the Wireshark plugins directory.
   - On Windows: `<Wireshark Install Directory>/plugins`. If portable `<Wireshark Install Directory>/data/plugins`
   - On macOS: `/Applications/Wireshark/Contents/PlugIns/wireshark`.
   - On Linux: `/usr/lib/wireshark/plugins`.
3. Launch Wireshark and verify that the plugin is loaded. You should see the "B3.ENTRYPOINT.SBE"
   ![analyze_menu.png](img/analyze_menu.png)

## SBE Template
- [Version 8.0.0](https://www.b3.com.br/data/files/8C/11/68/80/2DD3B810EE51F2B8AC094EA8/b3-entrypoint-messages-8.0.0.xml)
- [Version 8.1.1](https://www.b3.com.br/data/files/9D/06/64/34/E569F8103F2D05F8AC094EA8/b3-entrypoint-messages-8.1.1.xml)

## Limitations
- It may not handle all possible variations of SBE messages or custom extensions.

## Contributing
Contributions to this Wireshark plugin are welcome. If you encounter any issues or would like to add new features, please open an issue or submit a pull request.

Feel free to modify this template to suit your specific needs. Let me know if you need any further assistance!