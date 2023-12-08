rule Linux_Trojan_Gafgyt_8d4e4f4a
{
	meta:
		author = "Elastic Security"
		id = "8d4e4f4a-b3ea-4f93-ada2-2c88bb5d806d"
		fingerprint = "9601c7cf7f2b234bc30d00e1fc0217b5fa615c369e790f5ff9ca42bcd85aea12"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint 8d4e4f4a"
		filetype = "executable"

	strings:
		$a = { 50 00 FD FD 00 00 00 31 FD 48 FD FD 01 00 00 00 49 FD FD 04 }

	condition:
		all of them
}
