# xordump

In some cases, resulting lsass.exe minidump files are signatured by AV and deleted. It's not
unusual for the binary that initiated the lsass dump to be left on disk and not treated as
malicious. 

The dll loaded into this bin for minidumping (dgbhelp) _ALWAYS_ writes the minidump to
disk, but before this binary closes the file handle, it re-reads the contents into memory, closes
the handle and immediately deletes the file. 

There may exist a race between Go deleting the minidump file after a `close(handle)` and with AV
detecting and deleting the file. In either case, the output is safe in memory and passed to a Xor
function which then writes the data to disk.

**OPSEC consideration** If you lose the race, AV may see the dumpfile and say something.

miniDump and seDebug code swiped from Merlin C2, written by @C-Sto

## Building / Usage

Running `make` should build the windows exe and the shellcode that can be injected. Go 1.15+ is
required because of the additional PIE (position independence) flag introduced.
