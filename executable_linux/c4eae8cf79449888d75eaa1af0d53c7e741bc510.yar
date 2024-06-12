rule Linux_Generic_Threat_cb825102
{
	meta:
		author = "Elastic Security"
		id = "cb825102-0b03-4885-9f73-44dd0cf2d45c"
		fingerprint = "e23ac81c245de350514c54f91e8171c8c4274d76c1679500d6d2b105f473bdfc"
		creation_date = "2024-02-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "4e24b72b24026e3dfbd65ddab9194bd03d09446f9ff0b3bcec76efbb5c096584"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic threat on Linux systems"
		filetype = "executable"

	strings:
		$a1 = { 5B 2B 5D 20 72 65 73 6F 6C 76 69 6E 67 20 72 65 71 75 69 72 65 64 20 73 79 6D 62 6F 6C 73 2E 2E 2E }

	condition:
		all of them
}
