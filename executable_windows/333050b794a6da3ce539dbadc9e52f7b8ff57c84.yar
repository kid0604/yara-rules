rule APT10_redleaves_dll
{
	meta:
		description = "RedLeaves loader dll"
		author = "JPCERT/CC Incident Response Group"
		hash = "3938436ab73dcd10c495354546265d5498013a6d17d9c4f842507be26ea8fafb"
		os = "windows"
		filetype = "executable"

	strings:
		$a2a = {40 3D ?? ?? 06 00 7C EA 6A 40 68 00 10 00 00 68 ?? ?? 06 00 6A 00 FF 15 ?? ?? ?? ?? 85 C0}

	condition:
		all of them
}
