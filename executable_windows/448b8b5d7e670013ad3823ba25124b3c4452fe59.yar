import "pe"

rule INDICATOR_EXE_Packed_Babel
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Babel"
		snort = "930043-930044"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "BabelObfuscatorAttribute" fullword ascii
		$m1 = ";babelvm;smoketest" ascii wide
		$m2 = { 62 00 61 00 62 00 65 00 6c 00 76 00 6d [1-20] 73 00 6d 00 6f 00 6b 00 65 00 74 00 65 00 73 00 74 }
		$m3 = "babelvm" wide
		$m4 = "smoketest" wide
		$m5 = /lic[A-F0-9]{8}/ ascii wide

	condition:
		(( uint16(0)==0x5a4d and 1 of ($s*)) or (2 of ($m*)))
}
