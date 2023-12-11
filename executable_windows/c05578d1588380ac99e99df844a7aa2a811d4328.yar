import "pe"

rule INDICATOR_EXE_Packed_Loader
{
	meta:
		author = "ditekSHen"
		description = "Detects packed executables observed in Molerats"
		os = "windows"
		filetype = "executable"

	strings:
		$l1 = "loaderx86.dll" fullword ascii
		$l2 = "loaderx86" fullword ascii
		$l3 = "loaderx64.dll" fullword ascii
		$l4 = "loaderx64" fullword ascii
		$s1 = "ImportCall_Zw" wide
		$s2 = "DllInstall" ascii wide
		$s3 = "evb*.tmp" fullword wide
		$s4 = "WARNING ZwReadFileInformation" ascii
		$s5 = "LoadLibrary failed with module " fullword wide

	condition:
		uint16(0)==0x5a4d and 2 of ($l*) and 4 of ($s*)
}
