import "pe"

rule ProcessHacker_alt_1
{
	meta:
		description = "mal - file ProcessHacker.exe"
		author = "TheDFIRReport"
		date = "2021-11-29"
		hash1 = "d4a0fe56316a2c45b9ba9ac1005363309a3edc7acf9e4df64d326a0ff273e80f"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\taskmgr.exe" fullword wide
		$x2 = "D:\\Projects\\processhacker2\\bin\\Release32\\ProcessHacker.pdb" fullword ascii
		$x3 = "ProcessHacker.exe" fullword wide
		$x4 = "kprocesshacker.sys" fullword wide
		$x5 = "ntdll.dll!NtDelayExecution" fullword wide
		$x6 = "ntdll.dll!ZwDelayExecution" fullword wide
		$s7 = "PhInjectDllProcess" fullword ascii
		$s8 = "_PhUiInjectDllProcess@8" fullword ascii
		$s9 = "logonui.exe" fullword wide
		$s10 = "Executable files (*.exe;*.dll;*.ocx;*.sys;*.scr;*.cpl)" fullword wide
		$s11 = "\\x86\\ProcessHacker.exe" fullword wide
		$s12 = "user32.dll!NtUserGetMessage" fullword wide
		$s13 = "ntdll.dll!NtWaitForKeyedEvent" fullword wide
		$s14 = "ntdll.dll!ZwWaitForKeyedEvent" fullword wide
		$s15 = "ntdll.dll!NtReleaseKeyedEvent" fullword wide
		$s16 = "ntdll.dll!ZwReleaseKeyedEvent" fullword wide
		$s17 = "\\kprocesshacker.sys" fullword wide
		$s18 = "\\SystemRoot\\system32\\drivers\\ntfs.sys" fullword wide
		$s19 = "_PhExecuteRunAsCommand2@36" fullword ascii
		$s20 = "_PhShellExecuteUserString@20" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <4000KB and 1 of ($x*) and 4 of them
}
