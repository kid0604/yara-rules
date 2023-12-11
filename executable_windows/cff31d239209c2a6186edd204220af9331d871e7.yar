rule Windows_Trojan_IcedID_f1ce2f0a
{
	meta:
		author = "Elastic Security"
		id = "f1ce2f0a-0d34-46a4-8e42-0906adf4dc1b"
		fingerprint = "1940c4bf5d8011dc7edb8dde718286554ed65f9e96fe61bfa90f6182a4b8ca9e"
		creation_date = "2021-02-28"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.IcedID"
		reference = "https://www.fireeye.com/blog/threat-research/2021/02/melting-unc2198-icedid-to-ransomware-operations.html"
		reference_sample = "b21f9afc6443548427bf83b5f93e7a54ac3af306d9d71b8348a6f146b2819457"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID variant f1ce2f0a"
		filetype = "executable"

	strings:
		$a = { 8B C8 8B C6 F7 E2 03 CA 8B 54 24 14 2B D0 8B 44 24 14 89 54 }

	condition:
		all of them
}
