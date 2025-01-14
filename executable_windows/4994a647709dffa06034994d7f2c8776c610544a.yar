rule malware_spygrace
{
	meta:
		description = "SpyGrace"
		author = "JPCERT/CC Incident Response Group"
		hash = "067da693b92b006f0a28b2de103529b5390556b1975f0ef2068c7c7f3ddb1242"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%d%02d%02d-%02d%02d%02d.jpg" ascii wide
		$s2 = "&c007=true" ascii wide
		$s3 = "uid" ascii wide
		$s4 = "Mozilla/5.0" ascii wide
		$s5 = "(10 min)" ascii wide
		$s6 = "\\\\.\\pipe\\async_pipe" ascii wide
		$c1 = {34 ?? [0-3] FE C8 88 02 4? FF C?}
		$c2 = {41 [2-3] C0 E8 02 88 [2-3] 41 [5-6] C0 E1 04 41 [2-3] C0 E8 04 02 C8 88 [2-3] 41 [2-3] 80 E1 0F C0 E1 02 [3] C0 E8 06 02 C8}

	condition:
		uint16(0)==0x5A4D and 3 of ($s*) and 1 of ($c*)
}
