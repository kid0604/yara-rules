rule Windows_Generic_MalCert_7749cda8
{
	meta:
		author = "Elastic Security"
		id = "7749cda8-9351-4149-92f8-bebf35b891b6"
		fingerprint = "82adbaa79a1a2e966593692c9d1e9c2ee103d306f675596bcf1c58a59208756f"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "e0f9e51835788efa869e932aab139241e0363f6b44fe1c6c230cc26b83701b65"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 6D 30 BD 4D AC 27 22 DE D1 22 24 7C 01 28 6F B1 }

	condition:
		all of them
}
