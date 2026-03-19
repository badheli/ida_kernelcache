#
# ida_kernelcache/compat.py
#
# IDA API compatibility layer for IDA 9.x+
#
# IDA 9.x removed or relocated many APIs that existed in IDA 7.x/8.x.
# This module provides transparent shims so the rest of the codebase
# can work against both old and new SDK versions without per-call guards.
#

import idaapi
import idc
import ida_bytes
import ida_name

# ida_struct was removed in IDA 9.x.  In 9.x all struct operations go through
# idc wrappers (which still exist) or ida_typeinf.  We import conditionally and
# expose _HAS_IDA_STRUCT so fallback code can guard its usage.
try:
    import ida_struct as _ida_struct
    _HAS_IDA_STRUCT = True
except ImportError:
    _ida_struct = None
    _HAS_IDA_STRUCT = False

# ===========================================================================
# idaapi.get_inf_structure() replacements
# ---------------------------------------------------------------------------
# get_inf_structure() was removed in IDA 9.x.  The individual fields are now
# exposed as free functions in the ida_ida module.
# ===========================================================================

try:
    import ida_ida as _ida_ida

    def inf_is_64bit():
        """Return True if the current database is 64-bit."""
        return _ida_ida.inf_is_64bit()

    def inf_is_32bit():
        """Return True if the current database is 32-bit."""
        return _ida_ida.inf_is_32bit()

    def inf_is_be():
        """Return True if the current database is big-endian."""
        return _ida_ida.inf_is_be()

    def inf_get_min_ea():
        """Return the minimum effective address in the database."""
        return _ida_ida.inf_get_min_ea()

    def inf_get_max_ea():
        """Return the maximum effective address in the database."""
        return _ida_ida.inf_get_max_ea()

except (ImportError, AttributeError):
    # Older IDA (pre-9.x) – fall back to the now-removed get_inf_structure().
    def _get_inf():
        return idaapi.get_inf_structure()

    def inf_is_64bit():
        return _get_inf().is_64bit()

    def inf_is_32bit():
        return _get_inf().is_32bit()

    def inf_is_be():
        info = _get_inf()
        try:
            return info.is_be()
        except AttributeError:
            return bool(info.mf)

    def inf_get_min_ea():
        return _get_inf().min_ea

    def inf_get_max_ea():
        return _get_inf().max_ea


# ===========================================================================
# FF flag constants
# ---------------------------------------------------------------------------
# In IDA 9.x many FF_* constants were removed from idc and now live
# exclusively in ida_bytes.  We probe both locations so the rest of the
# codebase can use compat.FF_* uniformly.
# ===========================================================================

def _flag(name, fallback):
    """Return the first value found for *name* in ida_bytes then idc."""
    v = getattr(ida_bytes, name, None)
    if v is not None:
        return v
    v = getattr(idc, name, None)
    if v is not None:
        return v
    return fallback

FF_UNK   = _flag('FF_UNK',   0x00000000)
FF_BYTE  = _flag('FF_BYTE',  0x00000000)
FF_WORD  = _flag('FF_WORD',  0x10000000)
FF_DWORD = _flag('FF_DWORD', 0x20000000)
FF_QWORD = _flag('FF_QWORD', 0x30000000)
FF_OWORD = _flag('FF_OWORD', 0x40000000)
FF_DATA  = _flag('FF_DATA',  0x00000400)
FF_STRUCT = _flag('FF_STRUCT', 0x60000000)

# ===========================================================================
# Struct error constants
# ---------------------------------------------------------------------------
# STRUC_ERROR_* moved from idc to ida_struct in IDA 9.x.
# ===========================================================================

def _serr(name, fallback):
    if _ida_struct is not None:
        v = getattr(_ida_struct, name, None)
        if v is not None:
            return v
    v = getattr(idc, name, None)
    if v is not None:
        return v
    return fallback

STRUC_ERROR_MEMBER_NAME   = _serr('STRUC_ERROR_MEMBER_NAME',   -1)
STRUC_ERROR_MEMBER_OFFSET = _serr('STRUC_ERROR_MEMBER_OFFSET', -4)
STRUC_ERROR_MEMBER_UNIVAR = _serr('STRUC_ERROR_MEMBER_UNIVAR', -7)

# ===========================================================================
# Name-setting constants
# ---------------------------------------------------------------------------
# SN_CHECK / SN_AUTO moved from idc to ida_name in IDA 9.x.
# ===========================================================================

def _nflag(name, fallback):
    v = getattr(ida_name, name, None)
    if v is not None:
        return v
    v = getattr(idc, name, None)
    if v is not None:
        return v
    return fallback

SN_CHECK = _nflag('SN_CHECK', 0x01)
SN_AUTO  = _nflag('SN_AUTO',  0x04)


# ===========================================================================
# Function shims
# ===========================================================================

def has_user_name(flags):
    """Return True if *flags* indicates a user-defined name.

    Tries idc.hasUserName → ida_bytes.has_user_name → bitmask fallback.
    """
    fn = getattr(idc, 'hasUserName', None) or getattr(ida_bytes, 'has_user_name', None)
    if fn:
        return bool(fn(flags))
    # Fallback: test the UAS (user-assigned name) bit directly.
    ms_uname = getattr(ida_bytes, 'MS_UNAME', 0x00000800)
    return bool(flags & ms_uname)


def calc_gtn_flags(fromaddr, ea):
    """Return flags suitable for ida_name.get_ea_name / idc.get_name.

    Tries idc.calc_gtn_flags → ida_name.calc_gtn_flags → 0.
    """
    fn = (getattr(idc, 'calc_gtn_flags', None)
          or getattr(ida_name, 'calc_gtn_flags', None))
    if fn:
        return fn(fromaddr, ea)
    return 0


def set_type(mid_or_ea, type_str):
    """Set the type string on a member id or address.

    Tries the new lowercase idc.set_type first (IDA 9.x), then the old
    idc.SetType (IDA 7/8.x).
    """
    fn = getattr(idc, 'set_type', None) or getattr(idc, 'SetType', None)
    if fn:
        return bool(fn(mid_or_ea, type_str))
    return False


def is_union(sid):
    """Return True if the struct identified by *sid* is a union.

    Tries idc.is_union first; falls back to ida_struct.get_struc().is_union().
    """
    fn = getattr(idc, 'is_union', None)
    if fn:
        return bool(fn(sid))
    if _ida_struct is not None:
        struc = _ida_struct.get_struc(sid)
        if struc is not None:
            return bool(struc.is_union())
    return False


def add_struc(idx, name, is_union_flag):
    """Add a new struct/union to the database.

    Tries idc.add_struc; falls back to ida_struct.add_struc (IDA 7/8.x only).
    """
    fn = getattr(idc, 'add_struc', None)
    if fn:
        return fn(idx, name, is_union_flag)
    if _ida_struct is not None:
        return _ida_struct.add_struc(idx, name, bool(is_union_flag))
    return idaapi.BADADDR


def add_struc_member(sid, name, offset, flag, typeid, nbytes):
    """Add a member to a struct.

    Tries idc.add_struc_member; falls back to ida_struct.add_struc_member
    (IDA 7/8.x only). *typeid* == -1 means no associated type id (plain data).
    """
    fn = getattr(idc, 'add_struc_member', None)
    if fn:
        return fn(sid, name, offset, flag, typeid, nbytes)
    if _ida_struct is not None:
        struc = _ida_struct.get_struc(sid)
        if struc is None:
            return -1
        if typeid != -1:
            mt = idaapi.opinfo_t()
            mt.tid = typeid
            return _ida_struct.add_struc_member(struc, name, offset, flag, mt, nbytes)
        return _ida_struct.add_struc_member(struc, name, offset, flag, None, nbytes)
    return -1


def get_member_flag(sid, offset):
    """Return the flags of the struct member at *offset*.

    Tries idc.get_member_flag; falls back to member.flag (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_member_flag', None)
    if fn:
        return fn(sid, offset)
    if _ida_struct is not None:
        struc = _ida_struct.get_struc(sid)
        if struc is not None:
            member = _ida_struct.get_member(struc, offset)
            if member is not None:
                return member.flag
    return -1


def get_member_strid(sid, offset):
    """Return the struct id of the member type at *offset*.

    Tries idc.get_member_strid; falls back to member sub-struct id (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_member_strid', None)
    if fn:
        return fn(sid, offset)
    if _ida_struct is not None:
        struc = _ida_struct.get_struc(sid)
        if struc is not None:
            member = _ida_struct.get_member(struc, offset)
            if member is not None:
                sub = _ida_struct.get_sptr(member)
                if sub is not None:
                    return sub.id
    return idaapi.BADADDR


def get_member_id(sid, offset):
    """Return the id of the struct member at *offset*.

    Tries idc.get_member_id; falls back to member.id (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_member_id', None)
    if fn:
        return fn(sid, offset)
    if _ida_struct is not None:
        struc = _ida_struct.get_struc(sid)
        if struc is not None:
            member = _ida_struct.get_member(struc, offset)
            if member is not None:
                return member.id
    return idaapi.BADADDR


def get_member_offset(sid, name):
    """Return the byte offset of the named member, or -1 if not found.

    Tries idc.get_member_offset; falls back to get_member_by_name (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_member_offset', None)
    if fn:
        return fn(sid, name)
    if _ida_struct is not None:
        struc = _ida_struct.get_struc(sid)
        if struc is not None:
            member = _ida_struct.get_member_by_name(struc, name)
            if member is not None:
                return member.soff
    return -1


def get_struc_size(sid):
    """Return the size in bytes of struct *sid*.

    Tries idc.get_struc_size; falls back to ida_struct.get_struc_size (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_struc_size', None)
    if fn:
        return fn(sid)
    if _ida_struct is not None:
        return _ida_struct.get_struc_size(sid)
    return 0


def get_struc_name(sid):
    """Return the name of struct *sid*, or None if not found.

    Tries idc.get_struc_name; falls back to ida_struct.get_struc_name (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_struc_name', None)
    if fn:
        return fn(sid)
    if _ida_struct is not None:
        return _ida_struct.get_struc_name(sid)
    return None


def get_struc_id(name):
    """Return the struct id for *name*, or BADADDR if not found.

    Tries idc.get_struc_id; falls back to ida_struct.get_struc_id (IDA 7/8.x only).
    """
    fn = getattr(idc, 'get_struc_id', None)
    if fn:
        return fn(name)
    if _ida_struct is not None:
        return _ida_struct.get_struc_id(name)
    return idaapi.BADADDR


def set_struc_name(sid, name):
    """Rename struct *sid* to *name*.

    Tries idc.set_struc_name; falls back to ida_struct.set_struc_name (IDA 7/8.x only).
    """
    fn = getattr(idc, 'set_struc_name', None)
    if fn:
        return fn(sid, name)
    if _ida_struct is not None:
        return _ida_struct.set_struc_name(sid, name)
    return False
