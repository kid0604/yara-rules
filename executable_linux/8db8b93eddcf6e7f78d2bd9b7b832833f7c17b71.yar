rule Linux_Trojan_Gafgyt_d7f35b54
{
	meta:
		author = "Elastic Security"
		id = "d7f35b54-82a8-4ef0-8c8c-30a6734223e1"
		fingerprint = "d01db0f6a169d82d921c76801738108a2f0ef4ef65ea2e104fb80188a3bb73b8"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "79a75c8aa5aa0d1edef5965e1bcf8ba2f2a004a77833a74870b8377d7fde89cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with ID d7f35b54"
		filetype = "executable"

	strings:
		$a = { FD 48 FD 45 FD 48 FD FD FD FD FD FD FD FD FD 48 FD 45 FD 66 }

	condition:
		all of them
}
