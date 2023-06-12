# CVE-2023-2008

Proof of concept exploit for CVE-2023-2008, a bug in the udmabuf driver of the 
Linux kernel fixed in 5.19-rc4.

You can find a description of the bug and the exploitation strategy in our [blog post](https://labs.bluefrostsecurity.de/blog/cve-2023-2008.html).

The exploit was tested on a vulnerable Ubuntu 22.04, and it requires access to the `/dev/udmabuf` device. This is only accessible to users in the `kvm` group, so you may need to add your test user to this group when testing the exploit.

To test, simply compile with gcc and run the resulting binary.
