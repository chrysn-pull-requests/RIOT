TODO
====

This application is here to ensure that the `gcoap_forward_proxy` is at least compile tested.
A proper test will hopefully be implemented some day that replaces this stub.

A provided test script can be run as `./test.py "coap://[fe80::3c63:beff:fe85:ca96%tapbr0]"`;
running successfully to completion shows some properties of the proxy.
Still, that should be integrated so that `make test`, determining the attached node's IP address.
