rule Windows_Trojan_Zloader_4fe0f7f1
{
	meta:
		author = "Elastic Security"
		id = "4fe0f7f1-93c6-4397-acd5-1557608efaf4"
		fingerprint = "f340f41cc69930d24ffdae484d1080cd9ce5cb5e7720868c956923a5b8e6c9b1"
		creation_date = "2022-03-03"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Zloader"
		reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Zloader variant 4fe0f7f1"
		filetype = "executable"

	strings:
		$a = { 08 8B 75 F0 85 DB 8D 7D 94 89 45 E8 0F 45 FB 31 DB 85 F6 0F }

	condition:
		all of them
}
