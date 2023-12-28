rule APT10_redleaves_dropper1
{
	meta:
		description = "RedLeaves dropper"
		author = "JPCERT/CC Incident Response Group"
		hash = "5262cb9791df50fafcb2fbd5f93226050b51efe400c2924eecba97b7ce437481"
		os = "windows"
		filetype = "executable"

	strings:
		$v1a = ".exe"
		$v1b = ".dll"
		$v1c = ".dat"
		$a2a = {E8 ?? ?? FF FF 68 ?? 08 00 00 FF}
		$d2a = {83 C2 02 88 0E 83 FA 08}
		$d2b = {83 C2 02 88 0E 83 FA 10}

	condition:
		all of them
}
