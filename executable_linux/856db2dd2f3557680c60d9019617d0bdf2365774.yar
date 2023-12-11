rule Linux_Cryptominer_Xmrig_403b0a12
{
	meta:
		author = "Elastic Security"
		id = "403b0a12-8475-4e28-960b-ef33eabf0fcf"
		fingerprint = "785ac520b9f2fd9c6b49d8a485118eee7707f0fa0400b3db99eb7dfb1e14e350"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrig"
		reference_sample = "54d806b3060404ccde80d9f3153eebe8fdda49b6e8cdba197df0659c6724a52d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrig malware"
		filetype = "executable"

	strings:
		$a = { 00 28 03 1C C3 0C 00 C0 00 60 83 1C A7 71 00 00 00 68 83 5C D7 }

	condition:
		all of them
}
