# SRP-6a Android Library

This Android library is an implementation of the Secure Remote Password (SRP-6a)
password-authenticated secure channel protocol. This implementation allows to
establish a password-authenticated secure communication channel with our
[Java Card applet](https://github.com/mobilesec/secure-channel-srp6a-applet)
running on a secure element. The app uses the
[seek-for-android](https://code.google.com/p/seek-for-android/) implementation
of the Open Mobile API to communicate with secure elements. The secure channel
protocol implementation could also be used to communicate with contactless
smartcards over the NFC interface, however, we did not implement this interface
yet. Finally, our implementation provides a mutually authenticated secure channel
between an Android application and an applet running on a Java Card (e.g. a
secure element). The implementation uses a few minor modifications to the SRP
protocol presented our MoMM2014 paper (see LITERATURE section).

The test application in this repository should help you to get started with
integrating the library in your own Android app.



## DISCLAIMER

You are using this application at your own risk. *We are not responsible for any
damage caused by this application, incorrect usage or inaccuracies in this manual.*



## LITERATURE

- M. Hölzl, E. Asnake, R. Mayrhofer, and M. Roland: "*Mobile Application to Java Card Applet Communication using a Password-authenticated Secure Channel*," in Proceedings of the 12th International Conference on Advances in Mobile Computing & Multimedia (MoMM2014), pp. 147--156, ACM, December 2014.
