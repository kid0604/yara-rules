rule Linux_Trojan_Ladvix_81fccd74
{
	meta:
		author = "Elastic Security"
		id = "81fccd74-465d-4f2e-b879-987bc47828dd"
		fingerprint = "0e983107f38a6b2a739a44ab4d37c35c5a7d8217713b280a1786511089084a95"
		creation_date = "2021-06-28"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ladvix"
		reference = "2a183f613fca5ec30dfd82c9abf72ab88a2c57d2dd6f6483375913f81aa1c5af"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Ladvix"
		filetype = "executable"

	strings:
		$a = { 45 EA 00 00 48 8D 45 EA 48 8B 55 F0 0F B6 12 88 10 0F B7 45 EA 0F }

	condition:
		all of them
}
