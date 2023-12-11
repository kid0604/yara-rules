rule Windows_Trojan_Emotet_1943bbf2
{
	meta:
		author = "Elastic Security"
		id = "1943bbf2-56c0-443e-9208-cd8fc3b02d79"
		fingerprint = "df8b73d83a50a58ed8332b7580c970c2994aa31d2ac1756cff8e0cd1777fb8fa"
		creation_date = "2021-11-18"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Emotet"
		reference_sample = "5abec3cd6aa066b1ddc0149a911645049ea1da66b656c563f9a384e821c5db38"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Emotet with fingerprint 1943bbf2"
		filetype = "executable"

	strings:
		$a = { 66 83 38 5C 74 0A 83 C0 02 66 39 30 75 F2 EB 06 33 C9 66 89 }

	condition:
		all of them
}
