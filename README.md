WebSockets
==
Supporting material for WebSockets security presentations.

Send questions and suggestions to:
 mike(at)deadliestwebattacks.com
 [@CodexWebSecurum](https://twitter.com/CodexWebSecurum)

Follow the [blog](http://deadliestwebattacks.com).

Code Samples
--

### scapy/WebSockets.py
Proof-of-concept Scapy module for dissecting the WebSocket protocol using Python.

Download and install [Scapy][scapy-project] first.

There are still plenty of improvements to make:

 * Parse the HTTP handshake.
 * More robust support for non-text frames.
 * Create generators to produce packets.
 * Error handling.
 * Provide sample pcaps.

Presentations
--

[RSA US 2013][ASEC-F41]

[BayThreat 2012][bt2012]


[ASEC-F41]: http://deadliestwebattacks.com/2013/03/08/rsa-us-2013-asec-f41-slides/ "Using HTML5 WebSockets Securely"
[bt2012]: http://deadliestwebattacks.com/2012/12/07/baythreat-2012-websocket-presentation/ "Hacking with WebSockets"
[scapy-project]: http://www.secdev.org/projects/scapy/ "Scapy Project Home"
