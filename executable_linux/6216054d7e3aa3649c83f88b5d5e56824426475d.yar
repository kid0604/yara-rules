rule Linux_Hacktool_Portscan_6c6000c2
{
	meta:
		author = "Elastic Security"
		id = "6c6000c2-7e9a-457c-a745-00a3ac83a4bc"
		fingerprint = "3c893aebe688d70aebcb15fdc0d2780d2ec0589084c915ff71519ec29e5017f1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Portscan"
		reference_sample = "8877009fc8ee27ba3b35a7680b80d21c84ee7296bcabe1de51aeeafcc8978da7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Portscan"
		filetype = "executable"

	strings:
		$a = { 30 B9 0E 00 00 00 4C 89 D7 F3 A6 0F 97 C2 80 DA 00 84 D2 45 0F }

	condition:
		all of them
}
