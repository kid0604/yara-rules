rule MacOS_Cryptominer_Generic_d3f68e29
{
	meta:
		author = "Elastic Security"
		id = "d3f68e29-830d-4d40-a285-ac29aed732fa"
		fingerprint = "733dadf5a09f4972629f331682fca167ebf9a438004cb686d032f69e32971bd4"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Cryptominer.Generic"
		reference_sample = "d9c78c822dfd29a1d9b1909bf95cab2a9550903e8f5f178edeb7a5a80129fbdb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Cryptominer.Generic"
		filetype = "executable"

	strings:
		$a1 = "command line argument. See 'ethminer -H misc' for details." ascii fullword
		$a2 = "Ethminer - GPU ethash miner" ascii fullword
		$a3 = "StratumClient"

	condition:
		all of them
}
