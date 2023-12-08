import "pe"

rule upx_1_00_to_1_07 : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "19/03/2013"
		description = "UPX 1.00 to 1.07"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {60 BE 00 ?0 4? 00 8D BE 00 B0 F? FF ?7 8? [3] ?0 9? [0-9] 90 90 90 90 [0-2] 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0}

	condition:
		$str1 at pe.entry_point
}
