rule Windows_Generic_MalCert_2863b2d8
{
	meta:
		author = "Elastic Security"
		id = "2863b2d8-7759-44fa-81d3-4d196c426cd9"
		fingerprint = "aaffabc0edef460bb9c171bb9110468a26b6dbf176e4dfa957a2bf5915357f85"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "37223c02e25178395c05d47606b0d8c884a2b1151b59f701cc0d269d4408e1e5"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Generic.MalCert threat"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 56 4C 3F 65 1F E5 1A 68 50 4F C9 7C }

	condition:
		all of them
}
