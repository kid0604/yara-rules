import "pe"

rule INDICATOR_EXE_Packed_SmartAssembly
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with SmartAssembly"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "PoweredByAttribute" fullword ascii
		$s2 = "SmartAssembly.Attributes" fullword ascii
		$s3 = "Powered by SmartAssembly" ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}
