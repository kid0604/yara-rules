rule malware_spygrace_loader
{
	meta:
		description = "SpyGrace Loader"
		author = "JPCERT/CC Incident Response Group"
		hash = "067da693b92b006f0a28b2de103529b5390556b1975f0ef2068c7c7f3ddb1242"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mozilla/5.0" ascii wide
		$c1 = {66 41 83 34 00 ?? 41 FF C1 49 63 C1 49 83 C0 02 48 3B 42 ??}
		$c2 = {48 0F 47 85 ?? ?? ?? 00 42 0F B7 0C 00 66 41 33 CA 48 8D 85 ?? ?? ?? 00 84 D2}

	condition:
		uint16(0)==0x5A4D and $s1 and 1 of ($c*)
}
