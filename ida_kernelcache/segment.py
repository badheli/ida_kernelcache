#
# ida_kernelcache/segment.py
# Brandon Azad
#
# Functions for interacting with the segments of the kernelcache in IDA. No prior initialization is
# necessary.
#

import re
import struct as _struct
import idc
from ida_segment import SEGPERM_READ, SEGPERM_WRITE, SEGPERM_EXEC

from . import ida_utilities as idau
from . import kernel

_log = idau.make_log(0, __name__)

_LC_SEGMENT_64 = 0x19

# ---------------------------------------------------------------------------
# Direct Mach-O structure reader
# ---------------------------------------------------------------------------
# IDA 9.x removed idc.import_type(), so we can no longer rely on IDA's struct
# system to parse Mach-O headers.  Instead we read the raw bytes ourselves
# using Python's struct module (little-endian ARM64 only, which covers all
# modern iOS/macOS kernelcaches).

# (struct_format, field_names, fixed_size)
_MACHO_HDR64 = (
    '<IiiIIIII',   # 8 fields × 4 bytes = 32 bytes
    ['magic', 'cputype', 'cpusubtype', 'filetype', 'ncmds', 'sizeofcmds', 'flags', 'reserved'],
    32,
)
_LOAD_CMD = (
    '<II',         # 2 × 4 bytes = 8 bytes
    ['cmd', 'cmdsize'],
    8,
)
_SEG_CMD64 = (
    '<II16sQQQQiiII',  # 72 bytes
    ['cmd', 'cmdsize', 'segname', 'vmaddr', 'vmsize', 'fileoff', 'filesize',
     'maxprot', 'initprot', 'nsects', 'flags'],
    72,
)
_SECT64 = (
    '<16s16sQQIIIIIIII',  # 80 bytes
    ['sectname', 'segname', 'addr', 'size', 'offset', 'align', 'reloff',
     'nreloc', 'flags', 'reserved1', 'reserved2', 'reserved3'],
    80,
)


class _MachOObj:
    """Lightweight attribute bag returned by _read_macho_struct.

    Mimics the objectview interface used by the rest of this file:
      int(obj)  → start EA
      len(obj)  → struct size in bytes
    """
    def __init__(self, ea, size, fields):
        self._ea   = ea
        self._size = size
        for k, v in fields.items():
            setattr(self, k, v)

    def __int__(self):
        return self._ea

    def __len__(self):
        return self._size


def _read_macho_struct(ea, fmt_names_size):
    """Read a raw Mach-O struct from the database at *ea*.

    *fmt_names_size* is one of the _MACHO_HDR64 / _LOAD_CMD / … tuples above.
    Returns a _MachOObj on success, None on failure (short read, unmapped, etc.).
    """
    fmt, names, size = fmt_names_size
    data = idc.get_bytes(ea, size)
    if data is None or len(data) < size:
        return None
    values = _struct.unpack_from(fmt, data)
    return _MachOObj(ea, size, dict(zip(names, values)))


def _segments():
    seg_ea = idc.get_first_seg()
    while seg_ea != idc.BADADDR:
        name = idc.get_segm_name(seg_ea)
        yield seg_ea, name
        seg_ea = idc.get_next_seg(seg_ea)

def _fix_kernel_segments():
    for seg_off, seg_name in _segments():
        perms = None
        seg_name = seg_name.strip()
       
        if re.match(r".*[_.](got|const|cstring)$", seg_name, re.I):
            _log(1, "rw " + seg_name)
            perms = SEGPERM_READ | SEGPERM_WRITE
        elif re.match(r".*[_.](text|func|stubs)$", seg_name, re.I):
            _log(1, "rx " + seg_name)
            perms = SEGPERM_READ | SEGPERM_EXEC
        elif re.match(r".*[_.](data)$", seg_name, re.I):
            _log(1, "rw " + seg_name)
            perms = SEGPERM_READ | SEGPERM_WRITE

        if perms is not None:
            idc.set_segm_attr(seg_off, idc.SEGATTR_PERM, perms)


def _macho_segments_and_sections(ea):
    """Iterate through a Mach-O file's segments and sections.

    Reads structures directly from the IDA database via idc.get_bytes() so
    that no IDA struct definitions (mach_header_64 etc.) need to be imported.

    Each iteration yields:
        (segname, segstart, segend, [(sectname, sectstart, sectend), ...])
    """
    hdr = _read_macho_struct(ea, _MACHO_HDR64)
    if hdr is None:
        _log(0, 'Could not read mach_header_64 at {:#x}', ea)
        return
    nlc   = hdr.ncmds
    lc    = int(hdr) + len(hdr)
    lcend = lc + hdr.sizeofcmds
    while lc < lcend and nlc > 0:
        loadcmd = _read_macho_struct(lc, _LOAD_CMD)
        if loadcmd is None or loadcmd.cmdsize < 8:
            break
        if loadcmd.cmd == _LC_SEGMENT_64:
            segcmd = _read_macho_struct(lc, _SEG_CMD64)
            if segcmd is None:
                break
            segname  = idau.null_terminated(segcmd.segname)
            segstart = segcmd.vmaddr
            segend   = segstart + segcmd.vmsize
            sects    = []
            sc = int(segcmd) + len(segcmd)
            for _ in range(segcmd.nsects):
                sect = _read_macho_struct(sc, _SECT64)
                if sect is None:
                    break
                sectname  = idau.null_terminated(sect.sectname)
                sectstart = sect.addr
                sectend   = sectstart + sect.size
                sects.append((sectname, sectstart, sectend))
                sc += len(sect)
            yield (segname, segstart, segend, sects)
        lc  += loadcmd.cmdsize
        nlc -= 1

def _initialize_segments_in_kext(kext, mach_header, skip=[]):
    """Rename the segments in the specified kext."""
    def log_seg(segname, segstart, segend):
        _log(3, '+ segment {: <20} {:x} - {:x}  ({:x})', segname, segstart, segend,
            segend - segstart)
    def log_sect(sectname, sectstart, sectend):
        _log(3, '  section {: <20} {:x} - {:x}  ({:x})', sectname, sectstart, sectend,
                sectend - sectstart)
    def log_gap(gapno, start, end, mapped):
        mapped = 'mapped' if mapped else 'unmapped'
        _log(3, '  gap     {: <20} {:x} - {:x}  ({:x}, {})', gapno, start, end,
            end - start, mapped)
    def process_region(segname, name, start, end):
        assert end >= start
        if segname in skip:
            _log(2, 'Skipping segment {}', segname)
            return
        newname = '{}.{}'.format(segname, name)
        if kext:
            newname = '{}:{}'.format(kext, newname)
        if start == end:
            _log(2, 'Skipping empty region {} at {:x}', newname, start)
            return
        ida_segstart = idc.get_segm_start(start)
        if ida_segstart == idc.BADADDR:
            _log(0, "IDA doesn't think this is a real segment: {:x} - {:x}", start, end)
            return
        ida_segend = idc.get_segm_end(ida_segstart)
        if start != ida_segstart or end != ida_segend:
            _log(0, 'IDA thinks segment {} {:x} - {:x} should be {:x} - {:x}', newname, start, end,
                    ida_segstart, ida_segend)
            return
        _log(2, 'Rename {:x} - {:x}: {} -> {}', start, end, idc.get_segm_name(start), newname)
        idc.set_segm_name(start, newname)
    def process_gap(segname, gapno, start, end):
        mapped = idau.is_mapped(start)
        log_gap(gapno, start, end, mapped)
        if mapped:
            name = 'HEADER' if start == mach_header else '__gap_' + str(gapno)
            process_region(segname, name, start, end)
    for segname, segstart, segend, sects in _macho_segments_and_sections(mach_header):
        log_seg(segname, segstart, segend)
        lastend = segstart
        gapno   = 0
        for sectname, sectstart, sectend in sects:
            if lastend < sectstart:
                process_gap(segname, gapno, lastend, sectstart)
                gapno += 1
            log_sect(sectname, sectstart, sectend)
            process_region(segname, sectname, sectstart, sectend)
            lastend = sectend
        if lastend < segend:
            process_gap(segname, gapno, lastend, segend)
            gapno += 1

def initialize_segments():
    """Rename the kernelcache segments in IDA according to the __PRELINK_INFO data.

    Rename the kernelcache segments based on the contents of the __PRELINK_INFO dictionary.
    Segments are renamed according to the scheme '[<kext>:]<segment>.<section>', where '<kext>' is
    the bundle identifier if the segment is part of a kernel extension. The special region
    containing the Mach-O header is renamed '[<kext>:]<segment>.HEADER'.
    """
    # First fix kernel segments permissions
    _log(1, 'Fixing kernel segments permissions')
    _fix_kernel_segments()

    # Rename the kernel segments.
    _log(1, 'Renaming kernel segments')
    kernel_skip = ['__PRELINK_TEXT', '__PLK_TEXT_EXEC', '__PRELINK_DATA', '__PLK_DATA_CONST']
    _initialize_segments_in_kext(None, kernel.base, skip=kernel_skip)
    # Process each kext identified by the __PRELINK_INFO. In the new kernelcache format 12-merged,
    # the _PrelinkExecutableLoadAddr key is missing for all kexts, so no extra segment renaming
    # takes place.  On iOS 16+ kernelcaches __PRELINK_INFO may be absent or in a format we cannot
    # yet parse, so guard against prelink_info being None.
    if kernel.prelink_info is None:
        _log(0, 'No __PRELINK_INFO found; skipping per-kext segment renaming')
        return
    prelink_info_dicts = kernel.prelink_info.get('_PrelinkInfoDictionary', [])
    if not prelink_info_dicts:
        _log(1, '__PRELINK_INFO has no _PrelinkInfoDictionary; skipping per-kext segment renaming')
        return
    for kext_prelink_info in prelink_info_dicts:
        kext = kext_prelink_info.get('CFBundleIdentifier', None)
        mach_header = kext_prelink_info.get('_PrelinkExecutableLoadAddr', None)
        if kext is not None and mach_header is not None:
            orig_kext = idc.get_segm_name(mach_header).split(':', 1)[0]
            if not orig_kext:  # TODO: check if mach_header is valid
                continue
            if '.kpi.' not in kext and orig_kext != kext:
                _log(0, 'Renaming kext {} -> {}', orig_kext, kext)
            _log(1, 'Renaming segments in {}', kext)
            _initialize_segments_in_kext(kext, mach_header)

_kext_regions = []

def _initialize_kext_regions():
    """Get region information for each kext based on iOS 12's __PRELINK_INFO.__kmod_start.

    NOTE: This only accounts for __TEXT_EXEC, not the other segments."""
    kmod_start = idc.get_segm_by_sel(idc.selector_by_name('__PRELINK_INFO.__kmod_start'))
    if kmod_start == idc.BADADDR:
        return
    for kmod in idau.ReadWords(kmod_start, idc.get_segm_end(kmod_start)):
        _log(1, 'Found kmod {:x}', kmod)
        segments = list(_macho_segments_and_sections(kmod))
        if len(segments) != 1:
            _log(0, 'Skipping unrecognized kmod {:x}', kmod)
            continue
        segname, segstart, segend, sects = segments[0]
        if segname != '__TEXT_EXEC' or len(sects) != 1:
            _log(0, 'Skipping unrecognized kmod {:x}', kmod)
            continue
        kmod_name = 'kext.{:x}'.format(kmod)
        _log(1, 'Adding module:  {:x} - {:x}  {}', segstart, segend, kmod_name)
        _kext_regions.append((segstart, segend, kmod_name))

_initialize_kext_regions()

def kernelcache_kext(ea):
    """Return the name of the kext to which the given linear address belongs.

    Only works if segments have been renamed using initialize_segments().

    NOTE: Kexts are not well distinguished on the new iOS 12 merged kernelcache format. Do not rely
    on this function.
    """
    # TODO: This doesn't work on 12-merged kernelcaches!
    name = idc.get_segm_name(ea) or ''
    if ':' in name:
        return idc.get_segm_name(ea).split(':', 1)[0]
    if _kext_regions:
        for start, end, kext in _kext_regions:
            if start <= ea < end:
                return kext
    return None

