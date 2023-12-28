rule APT10_redleaves_dropper2
{
	meta:
		description = "RedLeaves dropper"
		author = "JPCERT/CC Incident Response Group"
		hash = "3f5e631dce7f8ea555684079b5d742fcfe29e9a5cea29ec99ecf26abc21ddb74"
		os = "windows"
		filetype = "executable"

	strings:
		$v1a = ".exe"
		$v1b = ".dll"
		$v1c = ".dat"
		$c2a = {B8 CD CC CC CC F7 E1 C1 EA 03}
		$c2b = {68 80 00 00 00 6A 01 6A 01 6A 01 6A 01 6A FF 50}

	condition:
		all of them
}
