rule Windows_Generic_Threat_79174b5c
{
	meta:
		author = "Elastic Security"
		id = "79174b5c-bc1d-40b2-b2e9-f3ddd3ba226c"
		fingerprint = "1e709e5cb8302ea19f9ee93e88f7f910f4271cf1ea2a6c92946fa26f68c63f4d"
		creation_date = "2023-12-18"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "c15118230059e85e7a6b65fe1c0ceee8997a3d4e9f1966c8340017a41e0c254c"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 83 EC 48 56 57 6A 0F 33 C0 59 8D 7D B9 F3 AB 8B 75 0C 6A 38 66 AB 8B 4E 14 AA 8B 46 10 89 4D FC 89 45 F8 59 C1 E8 03 83 E0 3F C6 45 B8 80 3B C1 72 03 6A 78 59 2B C8 8D 45 B8 51 50 56 }

	condition:
		all of them
}
