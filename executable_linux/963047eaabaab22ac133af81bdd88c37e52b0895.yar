rule Linux_Trojan_Gafgyt_83715433
{
	meta:
		author = "Elastic Security"
		id = "83715433-3dff-4238-8cdb-c51279565e05"
		fingerprint = "25ac15f4b903d9e28653dad0db399ebd20d4e9baabf5078fbc33d3cd838dd7e9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "3648a407224634d76e82eceec84250a7506720a7f43a6ccf5873f478408fedba"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 8B 45 08 88 10 FF 45 08 8B 45 08 0F B6 00 84 C0 75 DB C9 C3 55 }

	condition:
		all of them
}
