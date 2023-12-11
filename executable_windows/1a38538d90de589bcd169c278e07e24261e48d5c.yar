rule APT_Malware_PutterPanda_MsUpdater_2
{
	meta:
		description = "Detects Malware related to PutterPanda - MSUpdater"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "365b5537e3495f8ecfabe2597399b1f1226879b1"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "winsta0\\default" fullword ascii
		$s1 = "EXPLORER.EXE" fullword ascii
		$s2 = "WNetEnumResourceA" fullword ascii
		$s3 = "explorer.exe" fullword ascii
		$s4 = "CreateProcessAsUserA" fullword ascii
		$s5 = "HttpSendRequestExA" fullword ascii
		$s6 = "HttpEndRequestA" fullword ascii
		$s7 = "GetModuleBaseNameA" fullword ascii
		$s8 = "GetModuleFileNameExA" fullword ascii
		$s9 = "HttpSendRequestA" fullword ascii
		$s10 = "HttpOpenRequestA" fullword ascii
		$s11 = "InternetConnectA" fullword ascii
		$s12 = "Process32Next" fullword ascii
		$s13 = "Process32First" fullword ascii
		$s14 = "CreatePipe" fullword ascii
		$s15 = "EnumProcesses" fullword ascii
		$s16 = "LookupPrivilegeValueA" fullword ascii
		$s17 = "PeekNamedPipe" fullword ascii
		$s18 = "EnumProcessModules" fullword ascii
		$s19 = "PSAPI.DLL" fullword ascii
		$s20 = "SPSSSQ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <220KB and all of them
}
