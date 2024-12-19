# ws-p2p-rsa

**A Open-Source Peer-to-Peer RSA Communication**

ws-p2p-rsa provides a peer-to-peer (P2P) communication with RSA, using the [ws-p2p-framework](https://github.com/NotReeceHarris/ws-p2p-framework).

## Usage

To initiate a P2P connection between two peers, Alice and Bob, follow these steps:

```sh
# Alice
python3 main.py --target 192.168.0.1:8000 --host 192.168.0.2:8000

# Bob
python3 main.py --target 192.168.0.2:8000 --host 192.168.0.1:8000
```

## Requirements

- Python: Python 3.x is required.
- GUI Environment: Ensure you have a graphical environment; terminal support is planned for future updates.

## License

```
GNU GENERAL PUBLIC LICENSE
Version 3, 29 June 2007

Copyright (C) 2007 Free Software Foundation, Inc. <https://fsf.org/> Everyone is permitted to copy and distribute verbatim copies of this license document, but changing it is not allowed.
 ```
