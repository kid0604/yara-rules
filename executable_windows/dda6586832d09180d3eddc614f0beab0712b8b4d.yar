rule Windows_Generic_Threat_9f4a80b2
{
	meta:
		author = "Elastic Security"
		id = "9f4a80b2-e1ee-4825-a5e5-79175213da7d"
		fingerprint = "86946aea009f8debf5451ae7894529dbcf79ec104a51590d542c0d64a06f2669"
		creation_date = "2024-01-24"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "47d57d00e2de43f33cd56ff653adb59b804e4dbe37304a5fa6a202ee20b50c24"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 28 00 00 0A 2A 20 02 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 00 00 00 00 FE 01 39 0A 00 00 00 00 20 01 00 00 00 FE 0E 08 00 00 FE 0C 08 00 20 02 00 00 00 FE 01 39 05 00 00 00 38 05 00 00 00 38 }

	condition:
		all of them
}
