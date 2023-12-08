rule Linux_Trojan_Xorddos_410256ac
{
	meta:
		author = "Elastic Security"
		id = "410256ac-fc7d-47f1-b7b8-82f1ee9f2bfb"
		fingerprint = "aa7f1d915e55c3ef178565ed12668ddd71bf3e982dba1f2436c98cceef2c376d"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Xorddos"
		reference_sample = "15f44e10ece90dec1a6104d5be1effefa17614d9f0cfb2784305dab85367b741"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xorddos with fingerprint 410256ac"
		filetype = "executable"

	strings:
		$a = { 24 04 87 CA 8B 4D 0C 52 87 CA 59 03 D1 55 8B EC C9 6A 08 F7 }

	condition:
		all of them
}
