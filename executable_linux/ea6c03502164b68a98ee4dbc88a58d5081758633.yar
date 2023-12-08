rule Linux_Trojan_Gafgyt_6620ec67
{
	meta:
		author = "Elastic Security"
		id = "6620ec67-8f12-435b-963c-b44a02f43ef1"
		fingerprint = "9d68db5b3779bb5abe078f9e36dd9a09d4d3ad9274a3a50bdfa0e444a7e46623"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "b91eb196605c155c98f824abf8afe122f113d1fed254074117652f93d0c9d6b2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 6620ec67"
		filetype = "executable"

	strings:
		$a = { AF 93 64 1A D8 0B 48 93 64 0B 48 A3 64 11 D1 0B 41 05 E4 48 }

	condition:
		all of them
}
