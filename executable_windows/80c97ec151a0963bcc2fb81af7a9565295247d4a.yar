rule Windows_Generic_MalCert_b8c63d0f
{
	meta:
		author = "Elastic Security"
		id = "b8c63d0f-b546-4deb-8f23-c3d972bd8552"
		fingerprint = "b8a0cccc8663fc6dd9cd4db61349ee1a89c5709026ad6eb0070d64231483fca6"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "2f35445ba043097f38efbd160c6bdd6ba0f578165c295e6d31bfd179c3b6c4a1"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 23 A5 73 F8 85 C7 1A 52 D7 A6 E3 21 75 96 CD F9 }

	condition:
		all of them
}
