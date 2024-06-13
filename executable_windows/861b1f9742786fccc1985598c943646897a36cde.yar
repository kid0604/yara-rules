rule Windows_Generic_Threat_ba807e3e
{
	meta:
		author = "Elastic Security"
		id = "ba807e3e-13d8-49e0-ad99-32994d490e8b"
		fingerprint = "e6ea7577f8f21e778d21b4651bf55e66ec53fb6d80d68f2ab344261be50d03cc"
		creation_date = "2024-02-14"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "cabd0633b37e6465ece334195ff4cc5c3f44cfe46211165efc07f4073aed1049"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 7D 4A 36 35 2B 7E 2E 2C 2F 37 2C 3D 31 7E 3B 3D 30 30 2F 2A 7E 3C 39 7E 2C 29 30 7E 35 30 7E 5A 4F 4B 7E 31 2F 3A 39 70 }

	condition:
		all of them
}
