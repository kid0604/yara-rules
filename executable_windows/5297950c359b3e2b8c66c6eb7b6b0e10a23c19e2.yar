rule Windows_Trojan_Deimos_f53aee03
{
	meta:
		author = "Elastic Security"
		id = "f53aee03-74c3-4b40-8ae4-4f1bf35f88c8"
		fingerprint = "12a6d7f9e4f9a937bf1416443dd0d5ee556ac1f67d2b56ad35f9eac2ee6aac74"
		creation_date = "2021-09-18"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Deimos"
		reference_sample = "2c1941847f660a99bbc6de16b00e563f70d900f9dbc40c6734871993961d3d3e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Deimos"
		filetype = "executable"

	strings:
		$a1 = "\\APPDATA\\ROAMING" wide fullword
		$a2 = "{\"action\":\"ping\",\"" wide fullword
		$a3 = "Deimos" ascii fullword

	condition:
		all of ($a*)
}
