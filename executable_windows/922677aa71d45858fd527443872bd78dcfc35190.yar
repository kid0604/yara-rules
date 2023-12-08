rule INDICATOR_TOOL_Backstab
{
	meta:
		author = "ditekSHen"
		description = "Detect Backstab tool capable of killing antimalware protected processes by leveraging sysinternals Process Explorer (ProcExp) driver"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "NtLoadDriver: %x" fullword ascii
		$s2 = "POSIXLY_CORRECT" fullword ascii
		$s3 = "\\\\.\\PROCEXP" ascii
		$s4 = "ProcExpOpenProtectedProcess.DeviceIoControl: %" ascii
		$s5 = "ProcExpKillHandle.DeviceIoControl" ascii
		$s6 = "[%#llu] [%ws]: %ws" fullword ascii
		$s7 = "D:P(A;;GA;;;SY)(A;;GRGWGX;;;BA)(A;;GR" wide
		$s8 = "-k -d c:\\\\driver.sys" ascii
		$s9 = "backstab.exe -" ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
