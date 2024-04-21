rule APT10_HTSrl_signed
{
	meta:
		description = "HT Srl signature using APT10"
		author = "JPCERT/CC Incident Response Group"
		hash = "2965c1b6ab9d1601752cb4aa26d64a444b0a535b1a190a70d5ce935be3f91699"
		os = "windows"
		filetype = "executable"

	strings:
		$c = "IT"
		$st = "Italy"
		$l = "Milan"
		$ou = "Digital ID Class 3 - Microsoft Software Validation v2"
		$cn = "HT Srl"

	condition:
		all of them
}
