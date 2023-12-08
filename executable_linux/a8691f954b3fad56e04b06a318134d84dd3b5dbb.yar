rule Linux_Trojan_Gafgyt_fb14e81f
{
	meta:
		author = "Elastic Security"
		id = "fb14e81f-be2a-4428-9877-958e394a7ae2"
		fingerprint = "12b430108256bd0f57f48b9dbbea12eba7405c0b3b66a1c4b882647051f1ec52"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Gafgyt"
		reference = "0fd07e6068a721774716eb4940e2c19faef02d5bdacf3b018bf5995fa98a3a27"
		severity = "100"
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 4E 45 52 00 53 43 41 4E 4E 45 52 20 4F 4E 20 7C 20 4F 46 46 00 }

	condition:
		all of them
}
