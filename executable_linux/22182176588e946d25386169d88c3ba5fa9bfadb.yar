rule Linux_Cryptominer_Generic_e9ff82a8
{
	meta:
		author = "Elastic Security"
		id = "e9ff82a8-b8ca-45fb-9738-3ce0c452044f"
		fingerprint = "91e78b1777a0580f25f7796aa6d9bcbe2cbad257576924aecfe513b1e1206915"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "62ea137e42ce32680066693f02f57a0fb03483f78c365dffcebc1f992bb49c7a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a = { D9 4D 01 CA 4C 89 74 24 D0 4C 8B 74 24 E8 4D 31 D4 49 C1 C4 20 48 C1 }

	condition:
		all of them
}
