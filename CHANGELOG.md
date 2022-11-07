
# Mon 7 Nov 2022 - Raffe

Added binary and #cgo for `darwin/arm64` (Apple M1)

Updated `include/libdogecoin.h` and `libdogecoin.go` to match `0.1.1-dev`

```
# 0.1.1-dev @ Oct 4, 2022 (d3399f88d7c9e2cd5865f46c927d47eb4185cdc7)

-int verifyP2pkhAddress(char* p2pkh_pubkey, uint8_t len);
+int verifyP2pkhAddress(char* p2pkh_pubkey, size_t len);
 
-int sign_transaction(int txindex, char* amounts[], char* script_pubkey, char* privkey);
+int sign_transaction(int txindex, char* script_pubkey, char* privkey);
 
-int sign_raw_transaction(int inputindex, char* incomingrawtx, char* scripthex, int sighashtype, char* amount, char* privkey);
+int sign_raw_transaction(int inputindex, char* incomingrawtx, char* scripthex, int sighashtype, char* privkey);
```
