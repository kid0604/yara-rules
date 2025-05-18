rule Windows_Generic_MalCert_ac249f11
{
	meta:
		author = "Elastic Security"
		id = "ac249f11-12ed-434c-98c3-05d1c56c7a6a"
		fingerprint = "663a0260c32e4d1e5e1443e9f1b40e9ac0c5d8f1d2c8e2f7e4b42acb64b13fee"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "2449b3223695740b32c6c429ded948a49f20c569a8ebaae367936cc65a78a983"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 31 F7 D1 3B 36 05 F2 7A 3B 86 F2 BE }

	condition:
		all of them
}
