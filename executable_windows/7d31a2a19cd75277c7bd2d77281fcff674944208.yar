rule CN_Honker_sig_3389_xp3389
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file xp3389.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d776eb7596803b5b94098334657667d34b60d880"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "echo \"fdenytsconnections\"=dword:00000000 >> c:\\reg.reg" fullword ascii
		$s2 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server] >" ascii
		$s3 = "echo \"Tsenabled\"=dword:00000001 >> c:\\reg.reg" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
