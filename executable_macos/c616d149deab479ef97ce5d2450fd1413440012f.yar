rule MacOS_Trojan_Thiefquest_0f9fe37c
{
	meta:
		author = "Elastic Security"
		id = "0f9fe37c-77df-4d3d-be8a-c62ea0f6863c"
		fingerprint = "2e809d95981f0ff813947f3be22ab3d3c000a0d348131d5d6c8522447818196d"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Thiefquest"
		reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Thiefquest variant with fingerprint 0f9fe37c"
		filetype = "executable"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 33 71 6B 6E 6C 55 30 55 }

	condition:
		all of them
}
