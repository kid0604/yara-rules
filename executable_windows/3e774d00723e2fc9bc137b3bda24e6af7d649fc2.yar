rule Windows_Generic_MalCert_4b7c2e6d
{
	meta:
		author = "Elastic Security"
		id = "4b7c2e6d-5533-4d77-8345-2aeedd029e59"
		fingerprint = "3217845523b768b4380ca64b7a6894491cf115bb973ed4669fc7d62473dd2a94"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "df0553b9d93edbbc386466b1992dce170ba8e8d5e1cad6b7598a3609d5f51b5f"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 E4 0B 23 79 43 2D 73 AC B1 96 B9 D0 9A BC C5 87 }

	condition:
		all of them
}
