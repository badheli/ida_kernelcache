#
# ida_kernelcache.py
# Brandon Azad
#
# Entry point for the ida_kernelcache IDA plugin.
#
# When placed in ~/.idapro/plugins/, IDA 9.x requires every Python file in
# that directory to export a PLUGIN_ENTRY() function returning an idaapi.plugin_t
# subclass.  Older IDA (7/8.x) tolerated plain scripts here, but 9.x does not.
#
# The actual module is imported at the module level so that `ida_kernelcache`
# and `kc` are immediately available in the IDA Python console.
#

import idaapi

import ida_kernelcache          # noqa: F401  (imported for side-effects / REPL use)
import ida_kernelcache as kc    # noqa: F401


class _Ida_kernelcache_plugin(idaapi.plugin_t):
    """Thin IDA plugin wrapper for ida_kernelcache.

    The real work is done by importing ida_kernelcache at module level above.
    This class exists solely to satisfy IDA 9.x's requirement that every
    Python file in the plugins directory exports PLUGIN_ENTRY().
    """
    flags       = idaapi.PLUGIN_FIX   # Stay loaded so the module stays reachable
    comment     = "iOS kernelcache analysis tools (ida_kernelcache)"
    help        = "Provides ida_kernelcache / kc in the Python namespace"
    wanted_name = "ida_kernelcache"
    wanted_hotkey = ""

    def init(self):
        # ida_kernelcache is already imported at module level; nothing to do.
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return _Ida_kernelcache_plugin()
