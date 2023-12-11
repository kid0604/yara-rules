import "pe"

rule aspack : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "ASPack"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {60 E8 00 00 00 00 5D 81 ED 5D 3B 40 00 64 A1 30 00 00 00 0F B6 40 02 0A C0 74 04 33 C0 87 00 B9 [2] 00 00 8D BD B7 3B 40 00 8B F7 AC}

	condition:
		$str1 at pe.entry_point
}
