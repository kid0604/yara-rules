rule Linux_Trojan_Kinsing_85276fb4
{
	meta:
		author = "Elastic Security"
		id = "85276fb4-11f4-4265-9533-a96b42247f96"
		fingerprint = "966d53d8fc0e241250a861107317266ad87205d25466a4e6cdb27c3e4e613d92"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Kinsing"
		reference_sample = "b3527e3d03a30fcf1fdaa73a1b3743866da6db088fbfa5f51964f519e22d05e6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kinsing"
		filetype = "executable"

	strings:
		$a = { 65 5F 76 00 64 48 8B 0C 25 F8 FF FF FF 48 3B 61 10 76 38 48 83 }

	condition:
		all of them
}
