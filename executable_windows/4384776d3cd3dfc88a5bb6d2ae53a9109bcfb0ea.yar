rule Windows_Generic_MalCert_a632cd10
{
	meta:
		author = "Elastic Security"
		id = "a632cd10-98f6-458c-9486-a8b4eb501480"
		fingerprint = "da193c254a17c5052c14ccabc7f6d334e3ac1c8db8be5402f6d9f5eb552b3a80"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "74b3248b91f953f2db5784807e5e5cd86b8a425ed9cc3c1abe9bee68fcb081b7"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Generic.MalCert threat"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 11 44 D2 65 3D 4E 2A D1 9D B1 08 F8 66 19 49 81 }

	condition:
		all of them
}
