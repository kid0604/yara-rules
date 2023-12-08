rule Linux_Trojan_Mobidash_8679e1cb
{
	meta:
		author = "Elastic Security"
		id = "8679e1cb-407e-4554-8ef5-ece5110735c6"
		fingerprint = "7e517bf9e036410acf696c85bd39c720234b64aab8c5b329920a64f910c72c92"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash with fingerprint 8679e1cb"
		filetype = "executable"

	strings:
		$a = { 24 1C 89 F0 5B 5E 5F 5D C3 8D 76 00 8B 44 24 34 83 C6 01 8D 7C }

	condition:
		all of them
}
