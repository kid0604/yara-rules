rule Linux_Exploit_Local_66557224
{
	meta:
		author = "Elastic Security"
		id = "66557224-2c7a-4770-8333-8984d4a7b3f7"
		fingerprint = "88503c2e1e389866962704a8b19a47c22f758bb2cee9b76600e5d9bab125d4ca"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "f58151a2f653972e744822cdc420ab1c2b8b642877d3dfa2e8b2b6915e8edf40"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { FF FF 83 BD E4 FB FF FF FF 75 1A 83 EC 0C 68 24 }

	condition:
		all of them
}
