rule Windows_Trojan_Parallax_d72ec0e2
{
	meta:
		author = "Elastic Security"
		id = "d72ec0e2-cf33-4ed8-8d3f-66bc93e11f26"
		fingerprint = "897117bf47d993f5cb360a0c65b1bb3df72b594334c896c1d5e7e858df202d49"
		creation_date = "2022-09-05"
		last_modified = "2022-09-29"
		threat_name = "Windows.Trojan.Parallax"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Parallax"
		filetype = "executable"

	strings:
		$COM_png = { B9 01 00 00 00 6B D1 00 C6 44 15 D4 83 B8 01 00 00 00 C1 E0 00 C6 44 05 D4 B6 B9 01 00 00 00 D1 E1 C6 44 0D D4 33 BA 01 00 00 00 6B C2 03 C6 44 05 D4 28 B9 01 00 00 00 C1 E1 02 C6 44 0D D4 36 BA 01 00 00 00 6B C2 05 C6 44 05 D4 6B B9 01 00 00 00 6B D1 06 C6 44 15 D4 90 B8 01 00 00 00 6B C8 07 C6 44 0D D4 97 }
		$png_parse = { 8B 4D ?? 8B 04 B8 85 C9 74 ?? 8B F1 90 8A 08 8D 40 ?? 88 0C 1A 42 83 EE ?? 75 ?? 8B 4D ?? 8B 45 ?? 47 3B 7D ?? 72 ?? }
		$config_func = { C7 45 F8 68 74 74 70 8B ?? ?? 8B 02 89 ?? ?? 6A 08 8D ?? ?? 51 E8 ?? ?? ?? ?? 83 C4 08 8B ?? ?? 52 8D ?? ?? 50 8B ?? ?? 8B 51 0C FF D2 }
		$winnet_function = { B8 77 00 00 00 66 89 ?? ?? B9 69 00 00 00 66 89 ?? ?? BA 6E 00 00 00 66 89 ?? ?? B8 69 00 00 00 66 89 ?? ?? B9 6E 00 00 00 66 89 ?? ?? BA 65 00 00 00 66 89 ?? ?? B8 74 00 00 00 66 89 ?? ?? 33 C9 66 89 ?? ?? 8D ?? ?? 52 8B ?? ?? 8B 48 1C FF D1 }

	condition:
		$config_func or $winnet_function or $COM_png or $png_parse
}
