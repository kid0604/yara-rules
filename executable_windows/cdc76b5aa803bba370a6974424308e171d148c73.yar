rule Windows_Trojan_Raccoon_58091f64
{
	meta:
		author = "Elastic Security"
		id = "58091f64-2118-47f8-bcb2-407a3c62fa33"
		fingerprint = "ea819b46ec08ba6b33aa19dcd6b5ad27d107a8e37f3f9eb9ff751fe8e1612f88"
		creation_date = "2021-06-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Raccoon"
		reference_sample = "fe09bef10b21f085e9ca411e24e0602392ab5044b7268eaa95fb88790f1a124d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Raccoon"
		filetype = "executable"

	strings:
		$a = { 74 FF FF FF 10 8D 4D AC 53 6A 01 8D 85 60 FF FF FF 0F 43 85 60 FF }

	condition:
		all of them
}
