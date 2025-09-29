This contains POC information for a bug I found in Radare2, a [heap overflow in the RAP server protocol](https://github.com/radareorg/radare2/issues/24250).
Triggering this is extremely simple, using the following command:

```
echo -e "\x02\xff\xff\xfe\xfb" | nc 127.0.0.1 9999
```

Where 9999 is the RAP port.

Will either crash -- due to `memcpy_chk` usage, or leak data back depending on build type.

Another way is via:

```
echo -e "\x02\xff\xff\xbf\xff" | nc 127.0.0.1 9999
```

Which will crash after trying to write into a large buffer. 

As discussed in the issue, impact is debatable as radare2 remote access already allows A LOT BUT there is the radare sandbox feature to consider here.
If someone connecting to a sandoxed instance of radare was to use this there could be potential to bypass the sandbox.

The bug is fairly powerful as the first command allows leaking data without crashing the program, ASLR can be broken and future attempts could drop
directly into RCE depending on heap layout.
