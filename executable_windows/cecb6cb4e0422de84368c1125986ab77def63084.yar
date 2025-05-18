rule Windows_Generic_MalCert_ae04906b
{
	meta:
		author = "Elastic Security"
		id = "ae04906b-3731-4138-ba1a-f4f21033fcc6"
		fingerprint = "550ed59799b77be3c5c9f8d6edefb98f79ba4d148c553ce7138c45e0017a0646"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "e115cd3f7f9fb0d34d8ddb909da419a93ff441fd0c6a787afe9c130b03f6ff5e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Generic.MalCert malware"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 02 68 2C EB 56 82 17 E7 B0 DE 48 94 25 B0 D3 C2 }

	condition:
		all of them
}
