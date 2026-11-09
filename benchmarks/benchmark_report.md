# ARTEX CTF Automated Benchmark Suite (Node R3 Report)

- **Date**: 2026-11-09 14:01:10 UTC
- **Runner**: `http://ctf-runner:8790`
- **Total Evaluated**: 12 challenges across 5 domains (Crypto, Reverse, Pwn, Forensics, Web)
- **Solve Rate**: **100.0%** (12/12)
- **Total Duration**: 4.72s

| ID | Category | Challenge Name | Duration (ms) | Status | Expected Flag |
|---|---|---|---|---|---|
| `CRYPTO-01` | Crypto | RSA e=3 Low Exponent Attack | 190 | ✅ PASS | `flag{rsa_e3_cube_root_attack_success}` |
| `CRYPTO-02` | Crypto | Affine Cipher Modulo Inversion | 94 | ✅ PASS | `DASCTF{affine_mod_inverse_crypto_win}` |
| `CRYPTO-03` | Crypto | Multi-Layer Key Stream XOR | 100 | ✅ PASS | `moectf{xor_stream_multi_layer_decoded}` |
| `REV-01` | Reverse | ELF Logic Bypass & Deobfuscation | 114 | ✅ PASS | `hgame{simple_reverse_logic_bypass}` |
| `REV-02` | Reverse | UPX Unpack and Static Recovery | 71 | ✅ PASS | `geek{upx_unpack_and_extract_flag}` |
| `REV-03` | Reverse | Symbolic Execution with Z3 Solver | 204 | ✅ PASS | `ISCTF{angr_symbolic_solver_flag_found}` |
| `PWN-01` | Pwn | Stack Buffer Overflow (ret2win) | 594 | ✅ PASS | `ACTF{stack_overflow_ret2win_got_it}` |
| `PWN-02` | Pwn | Interactive Menu Challenge (PTY Session) | 418 | ✅ PASS | `CISCN{interactive_pty_menu_overflow}` |
| `PWN-03` | Pwn | Remote Target Proof-of-Work (PoW) | 131 | ✅ PASS | `WMCTF{pow_solved_and_flag_captured}` |
| `MISC-01` | Forensics | Image EXIF Metadata Flag Extraction | 196 | ✅ PASS | `VNCTF{exif_metadata_secret_extracted}` |
| `MISC-02` | Forensics | Binwalk Embedded Firmware Extraction | 95 | ✅ PASS | `flag{binwalk_nested_archive_extracted}` |
| `WEB-01` | Web | HTTP Header & Cookie Admin Bypass | 85 | ✅ PASS | `flag{http_admin_auth_bypass_success}` |
