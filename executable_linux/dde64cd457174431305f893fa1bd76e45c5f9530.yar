rule Linux_Trojan_Winnti_6f4ca425
{
	meta:
		author = "Elastic Security"
		id = "6f4ca425-5cd2-4c22-b017-b5fc02b3abc2"
		fingerprint = "dec25af33fc004de3a1f53e0c3006ff052f7c51c95f90be323b281590da7d924"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Winnti"
		reference = "161af780209aa24845863f7a8120aa982aa811f16ec04bcd797ed165955a09c1"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Winnti variant"
		filetype = "executable"

	strings:
		$a = { 89 E5 48 89 7D D8 48 8B 45 D8 0F B6 40 27 0F BE C0 89 45 F8 48 8B }

	condition:
		all of them
}
