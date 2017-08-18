apksigner
=========
A lightweight APK signing tool that can be run on Android devices.

It is available as a package in [Termux](https://termux.com) which can be installed with `pkg install apksigner`.

Usage
=====
Run as `apksigner [-p password] keystore input-apk output-apk`. This will use the specified keystore (or creating one if necessary) to create a signed and zipaligned output file.

License
=======
[Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0). Based on [zip-signer](https://code.google.com/p/zip-signer/) by Ken Ellinwood.
