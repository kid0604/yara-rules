rule Linux_Trojan_Gafgyt_859042a0
{
	meta:
		author = "Elastic Security"
		id = "859042a0-a424-4c83-944b-ed182b342998"
		fingerprint = "a27bcaa16edceda3dc5a80803372c907a7efd00736c7859c5a9d6a2cf56a8eec"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "41615d3f3f27f04669166fdee3996d77890016304ee87851a5f90804d6d4a0b0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant 859042a0"
		filetype = "executable"

	strings:
		$a = { 45 A8 48 83 C0 01 48 89 45 C0 EB 05 48 83 45 C0 01 48 8B 45 C0 0F }

	condition:
		all of them
}
