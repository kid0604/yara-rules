import "pe"

rule INDICATOR_EXE_Packed_Costura
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with Costura DotNetGuard"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "DotNetGuard" fullword ascii
		$s2 = "costura." ascii wide
		$s3 = "AssemblyLoader" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
