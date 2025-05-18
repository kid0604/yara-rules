rule Windows_Generic_MalCert_389a8f1e
{
	meta:
		author = "Elastic Security"
		id = "389a8f1e-01e3-47ee-a82b-7ffb0bea951e"
		fingerprint = "92e8d1c4b84592d10f58bd0528bc01493927ae77ed94aebf722aa806b60db93a"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "e87c99c87a42feba49f687bc7048ad3916297078d27a4aef3c037020158d216e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 0A B1 98 49 5D B9 8E 5E C6 1C D9 93 C6 A1 6F E7 }

	condition:
		all of them
}
