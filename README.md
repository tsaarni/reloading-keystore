
# Java KeyStore tutorial

![](https://github.com/tsaarni/java-keystore-tutorial/workflows/unit-tests/badge.svg)

## Description

This project contains tutorial for implementing custom `KeyStoreSpi` that supports following:

* Load certificates and private keys from `.pem` files instead of `.p12` or `.jks` keystores.
* Automatically reload credentials from disk when the underlying files have changed. This is sometimes called *hot-reload* or *hitless reload* to describe that the application does not need to be restarted.

Javadoc generated from the code can be read at https://tsaarni.github.io/java-keystore-tutorial.
