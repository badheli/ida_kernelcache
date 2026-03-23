#
# ida_kernelcache_reload.py
# Brandon Azad
#
# A helper script to *reload* ida_kernelcache (drop all cached modules and
# re-import).  Can be run as a script via IDA's File → Script File, or placed
# in the plugins directory (IDA 9.x requires PLUGIN_ENTRY in that case).
#

import sys
import idaapi

for mod in list(sys.modules.keys()):
    if 'ida_kernelcache' in mod:
        del sys.modules[mod]

import ida_kernelcache          # noqa: F401
import ida_kernelcache as kc    # noqa: F401


class _Ida_kernelcache_reload_plugin(idaapi.plugin_t):
    """Minimal plugin_t wrapper so IDA 9.x accepts this file from plugins/."""
    flags       = idaapi.PLUGIN_UNL   # Unload after init – this is a one-shot reload
    comment     = "Reload ida_kernelcache module"
    help        = ""
    wanted_name = "ida_kernelcache_reload"
    wanted_hotkey = ""

    def init(self):
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        pass


def PLUGIN_ENTRY():
    return _Ida_kernelcache_reload_plugin()
