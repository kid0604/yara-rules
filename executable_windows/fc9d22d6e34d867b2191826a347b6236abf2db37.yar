rule Windows_Trojan_Trickbot_9c0fa8fe
{
	meta:
		author = "Elastic Security"
		id = "9c0fa8fe-8d5f-4581-87a0-92a4ed1b32b3"
		fingerprint = "bd49ed2ee65ff0cfa95efc9887ed24de3882c5b5740d0efc6b9690454ca3f5dc"
		creation_date = "2021-07-13"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Trickbot"
		reference_sample = "f528c3ea7138df7c661d88fafe56d118b6ee1d639868212378232ca09dc9bfad"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Trickbot variant with fingerprint 9c0fa8fe"
		filetype = "executable"

	strings:
		$a = { 74 19 48 85 FF 74 60 8B 46 08 39 47 08 76 6A 33 ED B1 01 B0 01 }

	condition:
		all of them
}
