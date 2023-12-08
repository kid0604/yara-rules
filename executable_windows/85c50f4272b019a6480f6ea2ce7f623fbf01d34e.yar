import "pe"

rule obsidium : Packer
{
	meta:
		author = "Kevin Falcoz"
		date_create = "21/01/2013"
		last_edit = "17/03/2013"
		description = "Obsidium"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = {EB 02 [2] E8 25 00 00 00 EB 04 [4] EB 01 ?? 8B 54 24 0C EB 01 ?? 83 82 B8 00 00 00 23 EB 01 ?? 33 C0 EB 02 [2] C3 EB 02 [2] EB 04}

	condition:
		$str1 at pe.entry_point
}
