rule Windows_Trojan_Zloader_363c65ed
{
	meta:
		author = "Elastic Security"
		id = "363c65ed-e394-4a40-9c2a-a6f6fd284ed3"
		fingerprint = "33ae4cee122269f4342a3fd829236cbd303d8821b548ab93bbebc9dee3eb67f2"
		creation_date = "2022-03-03"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.Zloader"
		reference_sample = "161e657587361b29cdb883a6836566a946d9d3e5175e166a9fe54981d0c667fa"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Zloader"
		filetype = "executable"

	strings:
		$a = { 04 8D 4D E4 8D 55 E8 6A 00 6A 00 51 6A 00 6A 00 50 52 57 53 }

	condition:
		all of them
}
