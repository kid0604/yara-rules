rule Windows_Trojan_Zloader_79535191
{
	meta:
		author = "Elastic Security"
		id = "79535191-59df-4c78-9f62-b8614ef992d3"
		fingerprint = "ee3c4cf0d694119acfdc945a964e4fc0f51355eabca900ffbcc21aec0b3e1e3c"
		creation_date = "2022-03-03"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Zloader"
		reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Zloader with ID 79535191"
		filetype = "executable"

	strings:
		$a = { 28 4B 74 26 8B 46 FC 85 C0 74 F3 8B 4E F4 8B 16 39 C8 0F 47 C1 8B }

	condition:
		all of them
}
