rule MacOS_Trojan_Thiefquest_1f4bac78
{
	meta:
		author = "Elastic Security"
		id = "1f4bac78-ef2b-49cd-8852-e84d792f6e57"
		fingerprint = "e7d1e2009ff9b33d2d237068e2af41a8aa9bd44a446a2840c34955594f060120"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Thiefquest"
		reference_sample = "12fb0eca3903a3b39ecc3c2aa6c04fe5faa1f43a3d271154d14731d1eb196923"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Thiefquest variant 1f4bac78"
		filetype = "executable"

	strings:
		$a = { 77 47 72 33 31 30 50 6D 72 7A 30 30 30 30 30 37 33 00 32 33 4F 65 49 66 31 68 }

	condition:
		all of them
}
