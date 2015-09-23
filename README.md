# SRP Android Library

This Android library is an implementation of the Secure Remote Password
password-authenticated secure channel protocol. Supported protocol versions are the elliptic curve variant SRP-5 from [1] and the discrete logarithm variant SRP-6a described in [2]. The implementation allows to
establish a password-authenticated secure communication channel with our
Java Card applets for [EC-SRP](https://github.com/mobilesec/secure-channel-ec-srp-applet) or [SRP-6a](https://github.com/mobilesec/secure-channel-srp6a-applet)
running on a secure element. The app uses the
[seek-for-android](https://code.google.com/p/seek-for-android/) implementation
of the Open Mobile API to communicate with secure elements. The secure channel
protocol implementation could also be used to communicate with contactless
smartcards over the NFC interface, however, we did not implement this interface
yet. Finally, our implementation provides a mutually authenticated secure channel
between an Android application and an applet running on a Java Card (e.g. a
secure element). The implementation uses a few minor modifications to the SRP
protocol presented our MoMM2014 paper [3]. The extended version of this paper includes the elliptic curve variant of SRP and was published in IJPCC [4].

The test application in this repository should help you to get started with
integrating the library in your own Android app.



## DISCLAIMER

You are using this application at your own risk. *We are not responsible for any
damage caused by this application, incorrect usage or inaccuracies in this manual.*



## LITERATURE

[1] IEEE Computer Society, "*IEEE Standard Specifications for Password-Based Public-Key Cryptographic Techniques*," IEEE Std 1363.2-2008, pp. 1-127, Jan. 2009.

[2] T. Wu, "SRP-6: Improvements and Refinements to the Secure Remote Password Protocol," http://srp.stanford.edu/, Okt-2002. [Online]. Available: http://srp.stanford.edu/.

[3] M. Hölzl, E. Asnake, R. Mayrhofer, and M. Roland: "*Mobile Application to Java Card Applet Communication using a Password-authenticated Secure Channel*," in Proceedings of the 12th International Conference on Advances in Mobile Computing & Multimedia (MoMM2014), pp. 147--156, ACM, December 2014.

[4] M. Hölzl, E. Asnake, R. Mayrhofer, and M. Roland: "*A Password-authenticated Secure Channel for App to Java Card Applet Communication*," in International Journal of Pervasive Computing and Communications (IJPCC), In Press.
