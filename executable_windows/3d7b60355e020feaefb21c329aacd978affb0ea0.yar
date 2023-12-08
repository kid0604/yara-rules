rule CN_Honker_ACCESS_brute
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ACCESS_brute.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f552e05facbeb21cb12f23c34bb1881c43e24c34"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".dns166.co" ascii
		$s2 = "SExecuteA" ascii
		$s3 = "ality/clsCom" ascii
		$s4 = "NT_SINK_AddRef" ascii
		$s5 = "WINDOWS\\Syswm" ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and all of them
}
