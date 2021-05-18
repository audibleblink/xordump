# xordump

Made for use with Atomic Red Team.

```
Usage of xordump.exe:
  -in string
        Input file to Xor
  -m string
        [ dbghelp | dbgcore | comsvcs ] (default "dbghelp")
  -out string
        minidump outfile (default "minidump.dmp")
  -p string
        Process to dump (default "lsass.exe")
  -x int
        Single Byte Xor Key
```

In some cases, lsass.exe minidump files are signatured by AV and deleted. It's not
unusual for the binary that initiated the lsass dump to be left on disk and not treated as
malicious. 

The dll loaded into this bin for minidumping (dgbhelp) _ALWAYS_ writes the minidump to
disk, but before this binary closes the file handle, it re-reads the contents into memory, closes
the handle and immediately deletes the file. 

There may exist a race between Go deleting the minidump file after a `close(handle)` and with AV
detecting and deleting the file. In either case, the output is safe in memory and passed to a Xor
function which then re-writes the xor'd data to disk, where it can be safely exfilled.

**OPSEC consideration** If you lose the race, AV may see the dumpfile and say something.

Part of the miniDump and seDebug code written by @C-Sto

## Building / Usage

Running `make` should build the windows exe and the shellcode that can be injected. Go 1.15+ is
required because of the additional PIE (position independence) flag introduced.
