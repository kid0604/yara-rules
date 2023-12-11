rule Windows_Trojan_RedLineStealer_ed346e4c
{
	meta:
		author = "Elastic Security"
		id = "ed346e4c-7890-41ee-8648-f512682fe20e"
		fingerprint = "834c13b2e0497787e552bb1318664496d286e7cf57b4661e5e07bf1cffe61b82"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a = { 55 8B EC 8B 45 14 56 57 8B 7D 08 33 F6 89 47 0C 39 75 10 76 15 8B }

	condition:
		all of them
}
