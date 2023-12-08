rule Linux_Trojan_Mirai_01e4a728
{
	meta:
		author = "Elastic Security"
		id = "01e4a728-7c1c-479b-aed0-cb76d64dbb02"
		fingerprint = "d90477364982bdc6cd22079c245d866454475749f762620273091f2fab73c196"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 01e4a728"
		filetype = "executable"

	strings:
		$a = { 44 24 23 48 8B 6C 24 28 83 F9 01 4A 8D 14 20 0F B6 02 88 45 08 }

	condition:
		all of them
}
