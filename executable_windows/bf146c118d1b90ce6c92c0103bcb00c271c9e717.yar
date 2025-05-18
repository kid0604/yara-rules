rule Windows_Generic_MalCert_4cfcf573
{
	meta:
		author = "Elastic Security"
		id = "4cfcf573-8a49-41cf-a091-2d73d7ecc2ac"
		fingerprint = "077d6c2bf401e36bb612a532e6ae290762f9cb593f8daa8af0fc5d247ba50e76"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "12c98ce7a4c92244ae122acc5d50745ee3d2de3e02d9b1b8a7e53a7b142f652f"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 70 AA CF 51 0F 5C 8A 89 3C 51 04 B2 DB 31 56 33 }

	condition:
		all of them
}
