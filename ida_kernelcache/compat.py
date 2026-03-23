#
# ida_kernelcache/compat.py
#
# IDA 9.x API shims — no legacy fallbacks.
#
# All calls go directly to the IDA 9.x API.  If you need to support IDA 8.x
# or older, do not use this file.
#

import idaapi
import idc
import ida_bytes
import ida_name
import ida_ida

# ── inf queries ───────────────────────────────────────────────────────────────

def inf_is_64bit():   return ida_ida.inf_is_64bit()
def inf_is_32bit():   return ida_ida.inf_is_32bit_exactly()
def inf_is_be():      return ida_ida.inf_is_be()
def inf_get_min_ea(): return ida_ida.inf_get_min_ea()
def inf_get_max_ea(): return ida_ida.inf_get_max_ea()

# ── FF_ flags (live in ida_bytes in IDA 9.x) ─────────────────────────────────

FF_BYTE   = ida_bytes.FF_BYTE
FF_WORD   = ida_bytes.FF_WORD
FF_DWORD  = ida_bytes.FF_DWORD
FF_QWORD  = ida_bytes.FF_QWORD
FF_OWORD  = ida_bytes.FF_OWORD
FF_DATA   = ida_bytes.FF_DATA
FF_STRUCT = ida_bytes.FF_STRUCT
# FF_UNK is 0 in all versions
FF_UNK    = getattr(ida_bytes, 'FF_UNK', 0)

# ── Struct-member error codes (still in idc in IDA 9.x) ──────────────────────

STRUC_ERROR_MEMBER_NAME   = getattr(idc, 'STRUC_ERROR_MEMBER_NAME',   -1)
STRUC_ERROR_MEMBER_OFFSET = getattr(idc, 'STRUC_ERROR_MEMBER_OFFSET', -4)
STRUC_ERROR_MEMBER_UNIVAR = getattr(idc, 'STRUC_ERROR_MEMBER_UNIVAR', -7)

# ── Name-flag constants (moved to ida_name in IDA 7.x, confirmed in 9.x) ─────

SN_CHECK = ida_name.SN_CHECK
SN_AUTO  = ida_name.SN_AUTO

# ── Function shims ────────────────────────────────────────────────────────────

def has_user_name(flags):
    """Return True if *flags* indicates a user-defined name."""
    return bool(ida_bytes.has_user_name(flags))


def calc_gtn_flags(fromaddr, ea):
    """Return flags for idc.get_name / ida_name.get_ea_name."""
    fn = getattr(idc, 'calc_gtn_flags', None) or getattr(ida_name, 'calc_gtn_flags', None)
    return fn(fromaddr, ea) if fn else 0


def set_type(mid_or_ea, type_str):
    """Set the type string on a member id or address (idc.set_type in IDA 9.x)."""
    fn = getattr(idc, 'set_type', None)
    return bool(fn(mid_or_ea, type_str)) if fn else False


# ── Struct operations (idc wrappers, present in IDA 9.x) ─────────────────────

def is_union(sid):
    return bool(idc.is_union(sid))

def add_struc(idx, name, is_union_flag):
    return idc.add_struc(idx, name, is_union_flag)

def add_struc_member(sid, name, offset, flag, typeid, nbytes):
    return idc.add_struc_member(sid, name, offset, flag, typeid, nbytes)

def get_member_flag(sid, offset):
    return idc.get_member_flag(sid, offset)

def get_member_strid(sid, offset):
    return idc.get_member_strid(sid, offset)

def get_member_id(sid, offset):
    return idc.get_member_id(sid, offset)

def get_member_offset(sid, name):
    return idc.get_member_offset(sid, name)

def get_struc_size(sid):
    return idc.get_struc_size(sid)

def get_struc_name(sid):
    return idc.get_struc_name(sid)

def get_struc_id(name):
    return idc.get_struc_id(name)

def set_struc_name(sid, name):
    return idc.set_struc_name(sid, name)


# ── Binary search (ida_bytes.bin_search in IDA 9.x) ──────────────────────────

def find_binary(start_ea, range_end_ea, pattern, radix, sflag):
    """Search for a binary pattern using ida_bytes.bin_search (IDA 9.x)."""
    pat = ida_bytes.compiled_binpat_vec_t()
    enc = getattr(ida_bytes, 'PBSENC_DEF', 0)
    err = ida_bytes.parse_binpat_str(pat, start_ea, pattern, radix, enc)
    if err:
        return idaapi.BADADDR
    bflags = (ida_bytes.BIN_SEARCH_FORWARD
              if sflag & getattr(idaapi, 'SEARCH_DOWN', 1)
              else ida_bytes.BIN_SEARCH_BACKWARD)
    result = ida_bytes.bin_search(start_ea, range_end_ea, pat, bflags)
    # IDA 9.x returns (ea, match_size) tuple; older versions return ea directly.
    return result[0] if isinstance(result, tuple) else result
