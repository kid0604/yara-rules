rule Windows_Rootkit_R77_eb366abc
{
	meta:
		author = "Elastic Security"
		id = "eb366abc-d256-4dd2-ad97-898fdf905b8a"
		fingerprint = "beaa87877382a0cba0fcad6397b22bef2ff6dad8e3454ae517b529fbc76ff97a"
		creation_date = "2023-05-09"
		last_modified = "2023-06-13"
		threat_name = "Windows.Rootkit.R77"
		reference_sample = "21e7f69986987fc75bce67c4deda42bd7605365bac83cf2cecb25061b2d86d4f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Rootkit R77"
		filetype = "executable"

	strings:
		$a1 = { 8C 20 88 00 00 00 42 8B 44 21 10 42 8B 4C 21 1C 48 2B D0 49 }
		$a2 = { 53 00 4F 00 46 00 54 00 57 00 41 00 52 00 45 00 5C 00 24 00 37 00 37 00 63 00 6F 00 6E 00 66 00 69 00 67 00 }

	condition:
		all of them
}
