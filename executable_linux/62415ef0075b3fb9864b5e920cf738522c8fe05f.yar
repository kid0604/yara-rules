rule Linux_Trojan_Gafgyt_32a7edd2
{
	meta:
		author = "Elastic Security"
		id = "32a7edd2-175f-45b3-bf3d-8c842e4ae7e7"
		fingerprint = "d59183e8833272440a12b96de82866171f7ea0212cee0e2629c169fdde4da2a5"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 75 FD 48 FD 45 FD 0F FD 00 FD FD 0F FD FD 02 00 00 48 FD 45 }

	condition:
		all of them
}
