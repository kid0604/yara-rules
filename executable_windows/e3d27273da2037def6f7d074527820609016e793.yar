rule INDICATOR_TOOL_EXP_EternalBlue
{
	meta:
		author = "ditekSHen"
		description = "Detects Windows executables containing EternalBlue explitation artifacts"
		os = "windows"
		filetype = "executable"

	strings:
		$ci1 = "CNEFileIO_" ascii wide
		$ci2 = "coli_" ascii wide
		$ci3 = "mainWrapper" ascii wide
		$dp1 = "EXPLOIT_SHELLCODE" ascii wide
		$dp2 = "ETERNALBLUE_VALIDATE_BACKDOOR" ascii wide
		$dp3 = "ETERNALBLUE_DOUBLEPULSAR_PRESENT" ascii wide
		$dp4 = "//service[name='smb']/port" ascii wide
		$dp5 = /DOUBLEPULSAR_(PROTOCOL_|ARCHITECTURE_|FUNCTION_|DLL_|PROCESS_|COMMAND_|IS_64_BIT)/
		$cm1 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x64 --Function Rundll" ascii wide
		$cm2 = "--DllOrdinal 1 ProcessName lsass.exe --ProcessCommandLine --Protocol SMB --Architecture x86 --Function Rundll" ascii wide
		$cm3 = "--DaveProxyPort=0 --NetworkTimeout 30 --TargetPort 445 --VerifyTarget True --VerifyBackdoor True --MaxExploitAttempts 3 --GroomAllocations 12 --OutConfig" ascii wide

	condition:
		uint16(0)==0x5a4d and (2 of ($ci*)) or (2 of ($dp*)) or (1 of ($dp*) and 1 of ($ci*)) or (1 of ($cm*))
}
