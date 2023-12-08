import "pe"

rule MALWARE_Win_BlackMoon
{
	meta:
		author = "ditekSHen"
		description = "Detects executables using BlackMoon RunTime"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "blackmoon" fullword ascii
		$s2 = "BlackMoon RunTime Error:" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
