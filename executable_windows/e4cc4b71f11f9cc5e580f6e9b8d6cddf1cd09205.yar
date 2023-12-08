rule CN_Honker__D_injection_V2_32_D_injection_V2_32_D_injection_V2_32
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - from files D_injection_V2.32.exe, D_injection_V2.32.exe, D_injection_V2.32.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		super_rule = 1
		hash0 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		hash1 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		hash2 = "3a000b976c79585f62f40f7999ef9bdd326a9513"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "upfile.asp " fullword ascii
		$s2 = "[wscript.shell]" fullword ascii
		$s3 = "XP_CMDSHELL" fullword ascii
		$s4 = "[XP_CMDSHELL]" fullword ascii
		$s5 = "http://d99net.3322.org" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <10000KB and 4 of them
}
