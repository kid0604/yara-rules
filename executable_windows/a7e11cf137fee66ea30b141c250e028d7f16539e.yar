rule CN_Honker_exp_ms11046
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms11046.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "[*] Token system command" fullword ascii
		$s1 = "[*] command add user 90sec 90sec" fullword ascii
		$s2 = "[*] Add to Administrators success" fullword ascii
		$s3 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
