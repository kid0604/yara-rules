rule Linux_Cryptominer_Xmrminer_b17a7888
{
	meta:
		author = "Elastic Security"
		id = "b17a7888-dc12-4bb4-bc77-558223814e8b"
		fingerprint = "2b11457488e6098d777fb0d8f401cf10af5cd48e05248b89cb9e377d781b516c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "65c9fdd7c559554af06cd394dcebece1bc0fdc7dd861929a35c74547376324a6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { D4 FF C5 55 F4 C9 C5 F5 D4 CD C4 41 35 D4 C9 C5 B5 D4 C9 C5 C5 }

	condition:
		all of them
}
