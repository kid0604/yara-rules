rule Linux_Exploit_Local_6a9b5d50
{
	meta:
		author = "Elastic Security"
		id = "6a9b5d50-3cd4-4b64-9a52-713e1a8f02b2"
		fingerprint = "7eea1345492359984e9be089c3e7339b79927abcff0ae4a40a713e956bb25919"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "80ab71dc9ed2131b08b5b75b5a4a12719d499c6b6ee6819ad5a6626df4a1b862"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { E8 ?? F9 FF FF 83 7D D8 FF 75 14 BF ?? 13 40 00 }

	condition:
		all of them
}
