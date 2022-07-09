# XMLSec Library: Manual test of the keysstore feature

## xmlsec-mscng

- Import `tests/keys/rsakey-win.p12` (double-click on the file in Windows Explorer).

- Verify that the import happened, using `certmgr.msc`.

- Sign a file:
    ```
    win32/binaries/xmlsec.exe sign --crypto mscng --output out.xml tests/keysstore/keysstore.xml
    ```
- Verify signed file:
    ```
    win32/binaries/xmlsec.exe verify --crypto mscng out.xml
    ```