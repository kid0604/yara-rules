rule Windows_Trojan_Donutloader_f40e3759_alt_2
{
	meta:
		author = "Elastic Security"
		id = "f40e3759-2531-4e21-946a-fb55104814c0"
		fingerprint = "a6b9ccd69d871de081759feca580b034e3c5cec788dd5b3d3db033a5499735b5"
		creation_date = "2021-09-15"
		last_modified = "2022-01-13"
		threat_name = "Windows.Trojan.Donutloader"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Donutloader variant f40e3759_alt_2"
		filetype = "executable"

	strings:
		$x64 = { 06 B8 03 40 00 80 C3 4C 8B 49 10 49 8B 81 30 08 00 00 }
		$x86 = { 04 75 EE 89 31 F0 FF 46 04 33 C0 EB 08 83 21 00 B8 02 }

	condition:
		any of them
}
