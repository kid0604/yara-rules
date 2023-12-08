rule MacOS_Cryptominer_Generic_4e7d4488
{
	meta:
		author = "Elastic Security"
		id = "4e7d4488-2e0c-4c74-84f9-00da103e162a"
		fingerprint = "4e7f22e8084734aeded9b1202c30e6a170a6a38f2e486098b4027e239ffed2f6"
		creation_date = "2021-09-30"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Cryptominer.Generic"
		reference_sample = "e2562251058123f86c52437e82ea9ff32aae5f5227183638bc8aa2bc1b4fd9cf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Cryptominer Generic"
		filetype = "executable"

	strings:
		$a = { 69 73 20 66 69 65 6C 64 20 74 6F 20 73 68 6F 77 20 6E 75 6D 62 65 72 20 6F 66 }

	condition:
		all of them
}
