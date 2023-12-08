rule INDICATOR_TOOL_PWS_Mimikatz
{
	meta:
		author = "ditekSHen"
		description = "Detects Mimikatz"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "mimilib.dll" ascii
		$s2 = "mimidrv.sys" ascii
		$s3 = "mimikatz.exe" ascii
		$s4 = "\\mimidrv.pdb" ascii
		$s5 = "mimikatz" ascii
		$s6 = { 6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a }
		$s7 = { 5c 00 6d 00 69 00 6d 00 69 00 64 00 72 00 76 }
		$s8 = { 6d 00 69 00 6d 00 69 00 64 00 72 00 76 }
		$s9 = "Lecture KIWI_MSV1_0_" ascii
		$s10 = "Search for LSASS process" ascii
		$f1 = "SspCredentialList" ascii
		$f2 = "KerbGlobalLogonSessionTable" ascii
		$f3 = "LiveGlobalLogonSessionList" ascii
		$f4 = "TSGlobalCredTable" ascii
		$f5 = "g_MasterKeyCacheList" ascii
		$f6 = "l_LogSessList" ascii
		$f7 = "lsasrv!" ascii
		$f8 = "SekurLSA" ascii
		$f9 = /Cached(Unlock|Interative|RemoteInteractive)/ ascii
		$dll_1 = { c7 0? 00 00 01 00 [4-14] c7 0? 01 00 00 00 }
		$dll_2 = { c7 0? 10 02 00 00 ?? 89 4? }
		$sys_x86 = { a0 00 00 00 24 02 00 00 40 00 00 00 [0-4] b8 00 00 00 6c 02 00 00 40 00 00 00 }
		$sys_x64 = { 88 01 00 00 3c 04 00 00 40 00 00 00 [0-4] e8 02 00 00 f8 02 00 00 40 00 00 00 }

	condition:
		uint16(0)==0x5a4d and (2 of ($*) or 3 of ($f*) or all of ($dll_*) or any of ($sys_*))
}
