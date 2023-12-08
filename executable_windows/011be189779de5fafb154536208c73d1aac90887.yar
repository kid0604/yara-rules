import "pe"

rule pecompact2 : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "25/02/2013"
		description = "PECompact"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {B8 [3] 00 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43}

	condition:
		$str1 at pe.entry_point
}
