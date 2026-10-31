#!/usr/bin/env python3
"""
Telegram macOS Native (Swift) Binary Patcher (Universal: arm64 + x86_64)
Features:
1. Disable Channel Sponsored Messages (AdMessagesHistoryContext.activate & Impl.activate)
2. Disable Search Sponsored Peers (contacts.getSponsoredPeers / _internal_searchAdPeers)
3. Disable Copy / Forward / Save Protection (Peer.isCopyProtected, Message.isCopyProtected, etc.)
4. Remove Paid / Monetization Menus in Settings (Telegram Premium, Telegram Stars, TON/Balance,
   Telegram Business, Send a Gift, Wallet, and Set Emoji Status / Set Profile Color upsells)
"""

import struct
import sys
from pathlib import Path


def read_uleb(buf: bytes, idx: int):
    val = 0
    shift = 0
    while True:
        b = buf[idx]
        idx += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return val, idx


def parse_export_trie_swift_symbols(slice_buf: bytes):
    """
    Recover Swift symbols from LC_DYLD_INFO_ONLY export trie (including unstripped
    residual $s sub-trie left behind by strip).
    """
    ncmds, _ = struct.unpack("<II", slice_buf[16:24])
    pos = 32
    export_off, export_size = 0, 0
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", slice_buf[pos : pos + 8])
        if cmd in (0x22, 0x80000022):  # LC_DYLD_INFO / LC_DYLD_INFO_ONLY
            export_off, export_size = struct.unpack("<II", slice_buf[pos + 40 : pos + 48])
            break
        elif cmd == 0x80000033:  # LC_DYLD_EXPORTS_TRIE
            export_off, export_size = struct.unpack("<II", slice_buf[pos + 8 : pos + 16])
            break
        pos += cmdsize

    if not export_off or not export_size:
        return {}

    trie = slice_buf[export_off : export_off + export_size]

    # 1. Walk stripped root trie to find where overwritten region ends
    visited_root = set()
    max_end = 0

    def walk_root(offset: int):
        nonlocal max_end
        if offset in visited_root or offset >= len(trie):
            return
        visited_root.add(offset)
        idx = offset
        tsize, idx = read_uleb(trie, idx)
        idx += tsize
        num_children = trie[idx]
        idx += 1
        children = []
        for _ in range(num_children):
            end = trie.find(b"\x00", idx)
            idx = end + 1
            c_off, idx = read_uleb(trie, idx)
            children.append(c_off)
        if idx > max_end:
            max_end = idx
        for c_off in children:
            walk_root(c_off)

    walk_root(0)

    # 2. Walk unstripped residual "$s\x00" sub-trie
    s_pos = trie.rfind(b"$s\x00")
    if s_pos == -1:
        return {}
    start_node, _ = read_uleb(trie, s_pos + 3)

    symbols = {}
    visited = set()
    stack = [(start_node, "_$s")]

    while stack:
        offset, prefix = stack.pop()
        if offset in visited or offset < max_end or offset >= len(trie):
            continue
        visited.add(offset)
        try:
            idx = offset
            tsize, idx = read_uleb(trie, idx)
            if tsize > 0:
                t_idx = idx
                flags, t_idx = read_uleb(trie, t_idx)
                if (flags & 0x08) == 0:
                    sym_off, _ = read_uleb(trie, t_idx)
                    symbols[prefix] = sym_off
            idx += tsize
            if idx >= len(trie):
                continue
            num_children = trie[idx]
            idx += 1
            for _ in range(num_children):
                end = trie.find(b"\x00", idx)
                if end == -1:
                    break
                edge = trie[idx:end].decode("ascii", errors="ignore")
                idx = end + 1
                c_off, idx = read_uleb(trie, idx)
                if max_end <= c_off < len(trie):
                    stack.append((c_off, prefix + edge))
        except Exception:
            continue

    return symbols


def sign_extend(val: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (val & (sign_bit - 1)) - (val & sign_bit)


def patch_arm64_slice(buf: bytearray, slice_off: int, slice_size: int) -> int:
    slice_bytes = bytes(buf[slice_off : slice_off + slice_size])
    symbols = parse_export_trie_swift_symbols(slice_bytes)
    print(f"[arm64] Recovered {len(symbols)} Swift symbols from export trie")
    patched = 0

    def write_at(rel_off: int, patch_bytes: bytes, desc: str):
        nonlocal patched
        buf[slice_off + rel_off : slice_off + rel_off + len(patch_bytes)] = patch_bytes
        patched += 1
        print(f"  [arm64] Patched 0x10{rel_off:07x}: {desc}")

    # -------------------------------------------------------------------------
    # 1. Disable Channel Sponsored Ads (AdMessagesHistoryContext)
    # -------------------------------------------------------------------------
    ad_act = symbols.get("_$s12TelegramCore24AdMessagesHistoryContextC8activateyyF")
    if ad_act:
        write_at(ad_act, bytes.fromhex("c0035fd6"), "AdMessagesHistoryContext.activate() -> ret")
        # Find the closure right after activate()'s return (ret / retab) that calls AdMessagesHistoryContextImpl.activate()
        passed_ret = False
        for off in range(ad_act + 4, ad_act + 0x60, 4):
            ins = struct.unpack("<I", slice_bytes[off : off + 4])[0]
            if ins in (0xD65F03C0, 0xD65F0FFF):  # ret / retab
                passed_ret = True
                continue
            if passed_ret and (ins >> 26) == 0b100101:  # BL in closure
                target = (off + sign_extend(ins & 0x3FFFFFF, 26) * 4) & 0xFFFFFFFF
                write_at(target, bytes.fromhex("c0035fd6"), "AdMessagesHistoryContextImpl.activate() -> ret")
                break

    # -------------------------------------------------------------------------
    # 2. Disable Search Sponsored Peers (contacts.getSponsoredPeers)
    # -------------------------------------------------------------------------
    ad_peer_deinit = symbols.get("_$s12TelegramCore6AdPeerCfD")
    if ad_peer_deinit:
        for scan in range(ad_peer_deinit, ad_peer_deinit + 0x1000, 4):
            i0, i1, i2 = struct.unpack("<III", slice_bytes[scan : scan + 12])
            # ldr xN, [x0] (0xf9400000) followed by cmp xN, #1/#2 (0xf100001f) and b.ne (0x54000001)
            if (i0 & 0xFFC003E0) == 0xF9400000 and (i1 & 0xFF00001F) == 0xF100001F and (i2 & 0xFF00001F) == 0x54000001:
                write_at(
                    scan + 8,
                    bytes.fromhex("1f2003d5"),
                    "searchAdPeers response handler -> force .sponsoredPeersEmpty",
                )
                break

    # -------------------------------------------------------------------------
    # 3. Disable Copy / Forward / Save Protection
    # -------------------------------------------------------------------------
    copy_syms = [
        k
        for k in symbols
        if ("isCopyProtected" in k or "isCopyProtectionEnabled" in k)
        and (k.endswith("vg") or k.endswith("F"))
    ]
    for sym in sorted(copy_syms):
        off = symbols[sym]
        # mov w0, #0; ret
        write_at(off, bytes.fromhex("00008052c0035fd6"), f"{sym} -> return false")

    # -------------------------------------------------------------------------
    # 4. Remove Paid / Monetization Menus in Settings (AccountViewController)
    # -------------------------------------------------------------------------
    acct_start = symbols.get("_$s10SettingsUI21AccountViewControllerC15defaultBarTitleSSvg")
    spb_str = slice_bytes.find(b"stars_purchase_blocked\x00")
    if acct_start and spb_str != -1:
        spb_page = spb_str & ~0xFFF
        spb_pageoff = spb_str & 0xFFF
        ref_off = None
        for off in range(acct_start, acct_start + 0x4000, 4):
            i0, i1 = struct.unpack("<II", slice_bytes[off : off + 8])
            if (i0 & 0x9F000000) == 0x90000000:
                immlo = (i0 >> 29) & 3
                immhi = (i0 >> 5) & 0x7FFFF
                imm = sign_extend((immhi << 2) | immlo, 21) << 12
                page = (off & ~0xFFF) + imm
                if page == spb_page and (i1 & 0xFFC00000) == 0x91000000:
                    if ((i1 >> 10) & 0xFFF) == spb_pageoff:
                        ref_off = off
                        break

        if ref_off:
            # 4A. Main Paid Section (Telegram Premium, Stars, TON, Business, Send a Gift)
            for scan in range(ref_off - 4, ref_off - 0x120, -4):
                ins = struct.unpack("<I", slice_bytes[scan : scan + 4])[0]
                if (ins & 0xFFF8001F) == 0x37000000:  # tbnz w0, #0, ...
                    imm14 = sign_extend((ins >> 5) & 0x3FFF, 14)
                    if 0x80 < imm14 * 4 < 0x500:
                        b_ins = 0x14000000 | (imm14 & 0x3FFFFFF)
                        write_at(
                            scan,
                            struct.pack("<I", b_ins),
                            "Settings: Hide Premium / Stars / TON / Business / Send a Gift section",
                        )
                        break

            # 4B. Wallet menu row ("wallet_available" in the same function)
            wa_str = slice_bytes.find(b"wallet_available\x00")
            if wa_str != -1:
                wa_page = wa_str & ~0xFFF
                wa_pageoff = wa_str & 0xFFF
                for off in range(acct_start, ref_off, 4):
                    i0, i1 = struct.unpack("<II", slice_bytes[off : off + 8])
                    if (i0 & 0x9F000000) == 0x90000000:
                        immlo = (i0 >> 29) & 3
                        immhi = (i0 >> 5) & 0x7FFFF
                        imm = sign_extend((immhi << 2) | immlo, 21) << 12
                        if (off & ~0xFFF) + imm == wa_page and ((i1 >> 10) & 0xFFF) == wa_pageoff:
                            for wscan in range(off + 8, off + 0x50, 4):
                                wins = struct.unpack("<I", slice_bytes[wscan : wscan + 4])[0]
                                if (wins & 0xFFF80000) == 0x36000000:  # tbz wN, #0, ...
                                    imm14 = sign_extend((wins >> 5) & 0x3FFF, 14)
                                    b_ins = 0x14000000 | (imm14 & 0x3FFFFFF)
                                    write_at(
                                        wscan,
                                        struct.pack("<I", b_ins),
                                        "Settings: Hide Wallet menu row",
                                    )
                                    break
                            break

            # 4C. Top "Set Emoji Status / Set Profile Color" upsell rows
            peer_main = symbols.get("_$s12TelegramCore16peerViewMainPeery7Postbox0F0_pSgAC0fD0CF")
            if peer_main:
                for off in range(acct_start, ref_off, 4):
                    i0, i1 = struct.unpack("<II", slice_bytes[off : off + 8])
                    if (i0 >> 26) == 0b100101 and (i1 & 0xFF00001F) == 0xB4000000:  # bl + cbz x0
                        target = (off + sign_extend(i0 & 0x3FFFFFF, 26) * 4) & 0xFFFFFFFF
                        if target == peer_main:
                            write_at(
                                off,
                                bytes.fromhex("000080d2"),
                                "Settings: Hide Set Emoji Status & Set Profile Color upsell rows",
                            )
                            break

    return patched


def patch_x86_64_slice(buf: bytearray, slice_off: int, slice_size: int) -> int:
    slice_bytes = bytes(buf[slice_off : slice_off + slice_size])
    symbols = parse_export_trie_swift_symbols(slice_bytes)
    print(f"[x86_64] Recovered {len(symbols)} Swift symbols from export trie")
    patched = 0

    def write_at(rel_off: int, patch_bytes: bytes, desc: str):
        nonlocal patched
        buf[slice_off + rel_off : slice_off + rel_off + len(patch_bytes)] = patch_bytes
        patched += 1
        print(f"  [x86_64] Patched 0x10{rel_off:07x}: {desc}")

    # -------------------------------------------------------------------------
    # 1. Disable Channel Sponsored Ads (AdMessagesHistoryContext)
    # -------------------------------------------------------------------------
    ad_act = symbols.get("_$s12TelegramCore24AdMessagesHistoryContextC8activateyyF")
    if ad_act:
        write_at(ad_act, b"\xc3", "AdMessagesHistoryContext.activate() -> retq")
        for off in range(ad_act + 0x20, ad_act + 0x60):
            if slice_bytes[off] == 0xE8:  # callq rel32
                rel32 = struct.unpack("<i", slice_bytes[off + 1 : off + 5])[0]
                target = (off + 5 + rel32) & 0xFFFFFFFF
                if slice_bytes[target : target + 4] == b"\x55\x48\x89\xe5":
                    write_at(target, b"\xc3", "AdMessagesHistoryContextImpl.activate() -> retq")
                    break

    # -------------------------------------------------------------------------
    # 2. Disable Search Sponsored Peers (contacts.getSponsoredPeers)
    # -------------------------------------------------------------------------
    ad_peer_deinit = symbols.get("_$s12TelegramCore6AdPeerCfD")
    if ad_peer_deinit:
        idx = slice_bytes.find(b"\x48\x83\xfb\x02\x75", ad_peer_deinit, ad_peer_deinit + 0x1000)
        if idx != -1:
            write_at(
                idx + 4,
                b"\x90\x90",
                "searchAdPeers response handler -> force .sponsoredPeersEmpty",
            )

    # -------------------------------------------------------------------------
    # 3. Disable Copy / Forward / Save Protection
    # -------------------------------------------------------------------------
    copy_syms = [
        k
        for k in symbols
        if ("isCopyProtected" in k or "isCopyProtectionEnabled" in k)
        and (k.endswith("vg") or k.endswith("F"))
    ]
    for sym in sorted(copy_syms):
        off = symbols[sym]
        write_at(off, b"\x31\xc0\xc3", f"{sym} -> return false")

    # -------------------------------------------------------------------------
    # 4. Remove Paid / Monetization Menus in Settings (AccountViewController)
    # -------------------------------------------------------------------------
    acct_start = symbols.get("_$s10SettingsUI21AccountViewControllerC15defaultBarTitleSSvg")
    spb_str = slice_bytes.find(b"stars_purchase_blocked\x00")
    if acct_start and spb_str != -1:
        ref_off = None
        for off in range(acct_start, acct_start + 0x4000):
            if slice_bytes[off : off + 2] == b"\x48\x8d" and (slice_bytes[off + 2] & 0xC7) == 0x05:
                disp = struct.unpack("<i", slice_bytes[off + 3 : off + 7])[0]
                if (off + 7 + disp) == (spb_str - 0x20):
                    ref_off = off
                    break

        if ref_off:
            # 4A. Main Paid Section
            for scan in range(ref_off - 8, ref_off - 0x120, -1):
                if slice_bytes[scan : scan + 4] == b"\xa8\x01\x0f\x85":
                    rel32 = struct.unpack("<i", slice_bytes[scan + 4 : scan + 8])[0]
                    if 0x100 < rel32 < 0x600:
                        jmp_patch = b"\xe9" + struct.pack("<i", rel32 + 1) + b"\x90"
                        write_at(
                            scan + 2,
                            jmp_patch,
                            "Settings: Hide Premium / Stars / TON / Business / Send a Gift section",
                        )
                        break

            # 4B. Wallet menu row
            wa_str = slice_bytes.find(b"wallet_available\x00")
            if wa_str != -1:
                for off in range(acct_start, ref_off):
                    if slice_bytes[off : off + 2] == b"\x48\x8d" and (slice_bytes[off + 2] & 0xC7) == 0x05:
                        disp = struct.unpack("<i", slice_bytes[off + 3 : off + 7])[0]
                        if (off + 7 + disp) == (wa_str - 0x20):
                            for wscan in range(off + 7, off + 0x60):
                                if slice_bytes[wscan : wscan + 2] == b"\x0f\x84":
                                    rel32 = struct.unpack("<i", slice_bytes[wscan + 2 : wscan + 6])[0]
                                    if 0x40 < rel32 < 0x200:
                                        jmp_patch = b"\xe9" + struct.pack("<i", rel32 + 1) + b"\x90"
                                        write_at(
                                            wscan,
                                            jmp_patch,
                                            "Settings: Hide Wallet menu row",
                                        )
                                        break
                            break

            # 4C. Top "Set Emoji Status / Set Profile Color" upsell rows
            peer_main = symbols.get("_$s12TelegramCore16peerViewMainPeery7Postbox0F0_pSgAC0fD0CF")
            if peer_main:
                for off in range(acct_start, ref_off):
                    if (
                        slice_bytes[off] == 0xE8
                        and slice_bytes[off + 5 : off + 10] == b"\x48\x85\xc0\x0f\x84"
                    ):
                        rel32 = struct.unpack("<i", slice_bytes[off + 1 : off + 5])[0]
                        if ((off + 5 + rel32) & 0xFFFFFFFF) == peer_main:
                            write_at(
                                off,
                                b"\x31\xc0\x90\x90\x90",
                                "Settings: Hide Set Emoji Status & Set Profile Color upsell rows",
                            )
                            break

    return patched


def patch_telegram_binary(bin_path: Path):
    data = bytearray(bin_path.read_bytes())
    magic = struct.unpack(">I", data[:4])[0]
    total_patched = 0

    if magic == 0xCAFEBABE:
        nfat = struct.unpack(">I", data[4:8])[0]
        for i in range(nfat):
            cputype, _, offset, size, _ = struct.unpack(">IIIII", data[8 + i * 20 : 8 + (i + 1) * 20])
            if cputype == 0x0100000C:  # CPU_TYPE_ARM64
                total_patched += patch_arm64_slice(data, offset, size)
            elif cputype == 0x01000007:  # CPU_TYPE_X86_64
                total_patched += patch_x86_64_slice(data, offset, size)
    else:
        cputype = struct.unpack("<I", data[4:8])[0]
        if cputype == 0x0100000C:
            total_patched += patch_arm64_slice(data, 0, len(data))
        elif cputype == 0x01000007:
            total_patched += patch_x86_64_slice(data, 0, len(data))

    if total_patched == 0:
        raise RuntimeError("No patches were applied! Binary structure may have changed.")

    bin_path.write_bytes(data)
    print(f"\nSuccessfully applied {total_patched} binary patches to {bin_path}")


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("./Telegram.app/Contents/MacOS/Telegram")
    patch_telegram_binary(target)
