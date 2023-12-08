import "pe"

rule upx_0_80_to_1_24 : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "UPX 0.80 to 1.24"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {6A 60 68 60 02 4B 00 E8 8B 04 00 00 83 65 FC 00 8D 45 90 50 FF 15 8C F1 48 00 C7 45 FC FE FF FF FF BF 94 00 00 00 57}

	condition:
		$str1 at pe.entry_point
}
