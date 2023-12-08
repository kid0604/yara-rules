rule Linux_Trojan_Gafgyt_d996d335
{
	meta:
		author = "Elastic Security"
		id = "d996d335-e049-4052-bf36-6cd07c911a8b"
		fingerprint = "e9ccb8412f32187c309b0e9afcc3a6da21ad2f1ffa251c27f9f720ccb284e3ac"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "b511eacd4b44744c8cf82d1b4a9bc6f1022fe6be7c5d17356b171f727ddc6eda"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { D0 EB 0F 40 38 37 75 04 48 89 F8 C3 49 FF C8 48 FF C7 4D 85 C0 }

	condition:
		all of them
}
