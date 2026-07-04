# AnyDesk v9.7.8 - License Unlock Plan

## Architecture Summary

- **Outer PE**: `AnyDesk.exe` (7.9MB) = win_loader stub
  - XOR decrypt (LCG seed=0x55F4) + LZMA1 decompress
- **Inner PE**: `AnyDesk_inner.exe` (29MB) = PE32 DLL (win_app.pdb)
  - ImageBase = 0x10000000
  - .text: vaddr=0x1000, rawptr=0x400, size=0x10ad200
  - VA to foff: `foff = VA - 0x10000000 - 0x1000 + 0x400 = VA - 0x1000C00`

## License System Architecture

### License Type Enum
- 0 = Free (non-professional)
- 1 = Trial
- 2 = Pro
- 3 = Enterprise (highest)

### License Manager Object
- Stored at `[session_obj + 0x98]`
- VTable: `0x1195bf8c`
- `vtable[+0x90]` = `0x106cbde0` = license type getter (complex, delegates to 0x10df4069)
- `vtable[+0x94]` = `0x10072c10` = another license query
- Fallback: config key `0xd` via `0x1069af59`

### Nuclear Option Assessment
- License getter `0x106cbde0` is complex (calls 0x10df4069 with object state)
- Cannot simply patch return value — function has side effects
- **Decision: Use surgical patches instead**

## Feature Gate Analysis

### Pattern: `call check_fn -> test eax/al -> je/jne -> show error`

Each feature check follows: call license check, if fail show premium/error dialog.

---

## Patch List

### Already Patched (from previous work)

| # | Name | VA | Original | Patch | Effect |
|---|------|----|----------|-------|--------|
| 1 | countdown_skip | 0x10626bbb | `83 e8 00` | `33 c0 90` | Skip 60s disconnect countdown |
| 2 | banner_no_ui_add | 0x106c376f | `e8 f0 ff 6b 00` | `90 90 90 90 90` | No banner in UI |
| 3 | banner_formatter_ret | 0x1084e520 | `55 8b ec` | `33 c0 c2 10 00` | Banner formatter returns empty |

### New Patches (license unlock)

#### 4. Premium dialog #1 — skip upgrade prompt
- **VA**: `0x10670788`
- **Code**: `test eax, eax; je 0x106707e2` (74 58)
- **Patch**: `je` -> `jmp` (74 58 -> EB 58)
- **Effect**: Always skip premium dialog when feature check returns non-zero

#### 5. Premium dialog #2 — skip upgrade prompt
- **VA**: `0x106ea935` area
- **Need**: More context to identify exact patch byte

#### 6. Address book limit — bypass entry count limit
- **VA**: `0x108c2f4b`
- **Code**: `cmp eax, 1; jne 0x108c30bc` (0f 85 6b 01 00 00)
- **Patch**: `jne` -> `jmp` (0f 85 -> 90 e9) = NOP + jmp
- **Effect**: Skip address book entry limit check

#### 7. Screen recording — allow recording on all licenses
- **VA**: `0x105c3f19`
- **Code**: `jne 0x105c40cf` (0f 85 b0 01 00 00)
- **Patch**: `jne` -> `jmp` (0f 85 -> 90 e9)
- **Effect**: Always allow screen recording

#### 8. Screen recording check #2
- **VA**: `0x105c3f32`
- **Code**: `jne 0x105c3fc2` (0f 85 8a 00 00 00)
- **Patch**: `jne` -> `jmp` (0f 85 -> 90 e9)
- **Effect**: Bypass second recording check

#### 9. Session invitation — allow on all licenses
- **VA**: `0x10727b75`
- **Code**: `jne 0x10727b7e` (75 07)
- **Patch**: `jne` -> `jmp` (75 07 -> EB 07)
- **Effect**: Skip session invitation feature_disabled check

#### 10. Connection limit — bypass session count limit
- **VA**: `0x10735f6c` area
- **Code**: `sub eax, 0; je 0x10735f7b; sub eax, 1; je 0x10735f80`
- **Need**: Identify exact check that triggers conn_limit error
- **Approach**: Patch the switch to always take the "allowed" path

#### 11. Session queue limit — bypass request rate limit
- **VA**: `0x1081bf0f` area
- **Code**: Inside switch/jump table
- **Need**: Find the actual rate check, not just error display

## Implementation Steps

1. **Verify all patch bytes** at each VA location
2. **Write comprehensive patch script** combining all patches
3. **Re-encode** (LZMA1 + XOR) to produce final AnyDesk_patched.exe
4. **Test on Windows** — verify each feature is unlocked

## Limitations (Server-Side, NOT patchable)

- **Concurrent session routing** through AnyDesk relay servers
- **Connection priority/speed** on AnyDesk network
- **Server-side license validation** when connecting through relay
- **AnyDesk account features** (address book sync, session history on server)

## Files

- `patch_anydesk.py` — existing patcher (3 patches)
- `patch_anydesk_full.py` — new comprehensive patcher (all patches)
- `AnyDesk_inner.exe` — decoded inner PE for analysis
- `AnyDesk_patched.exe` — patched output
