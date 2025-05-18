rule Windows_Generic_MalCert_c9e89da2
{
	meta:
		author = "Elastic Security"
		id = "c9e89da2-9479-4c50-a867-48ae647122d8"
		fingerprint = "c72f85c5fd5090953fde7c4044f8fde2a6e0680757f088ef64bd8fb260f4ed46"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "251f3eecf4f6b846ff595a251bb85fad09f28b654c08d3c76a89ed4cc94197d2"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 01 FF 82 F4 00 3A 6F D1 5A B7 A3 EB CA 98 7F 60 }

	condition:
		all of them
}
