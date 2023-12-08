import "pe"

rule INDICATOR_EXE_Packed_nBinder
{
	meta:
		author = "ditekSHen"
		description = "Detects executables packed with nBinder"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "This file was created using nBinder" ascii
		$s2 = "Warning: Contains binded files that may pose a security risk." ascii
		$s3 = "a file created with nBinder" ascii
		$s4 = "name=\"NKProds.nBinder.Unpacker\" type=\"win" ascii
		$s5 = "<description>nBinder Unpacker. www.nkprods.com</description>" ascii
		$s6 = "nBinder Unpacker (C) NKProds" wide
		$s7 = "\\Proiecte\\nBin" ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}
