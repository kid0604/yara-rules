rule Windows_Trojan_Generic_02a87a20
{
	meta:
		author = "Elastic Security"
		id = "02a87a20-a5b4-44c6-addc-c70b327d7b2c"
		fingerprint = "fb25a522888efa729ee6d43a3eec7ade3d08dba394f3592d1c3382a5f7a813c8"
		creation_date = "2022-03-04"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = { 24 3C 8B C2 2B C1 83 F8 01 72 3A 8D 41 01 83 FA 08 89 44 24 38 8D 44 }

	condition:
		all of them
}
