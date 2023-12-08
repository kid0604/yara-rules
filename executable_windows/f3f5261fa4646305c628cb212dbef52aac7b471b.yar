rule CN_Tools_pc
{
	meta:
		description = "Chinese Hacktool Set - file pc.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "5cf8caba170ec461c44394f4058669d225a94285"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\svchost.exe" fullword ascii
		$s2 = "%s%08x.001" fullword ascii
		$s3 = "Qy001Service" fullword ascii
		$s4 = "/.MIKY" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
