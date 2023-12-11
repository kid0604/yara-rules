rule Linux_Trojan_Ircbot_bb204b81
{
	meta:
		author = "Elastic Security"
		id = "bb204b81-db58-434f-b834-672cdc25e56c"
		fingerprint = "66f9a8a31653a5e480f427d2d6a25b934c2c53752308eedb57eaa7b7cb7dde2e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ircbot"
		reference_sample = "6147481d083c707dc98905a1286827a6e7009e08490e7d7c280ed5a6356527ad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ircbot"
		filetype = "executable"

	strings:
		$a = { 0F 44 C8 4C 5E F8 8D EF 80 83 CD FF 31 DB 30 22 }

	condition:
		all of them
}
