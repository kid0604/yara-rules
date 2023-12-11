rule Linux_Cryptominer_Generic_2627921e
{
	meta:
		author = "Elastic Security"
		id = "2627921e-6c0d-4515-a09a-b2c99a59598d"
		fingerprint = "2551ece438a09700c825faa63caa3e21ced94c85bdaa5b1b0dd63603d4fa9bb6"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "350a8ceabd8495e66cc58885f1ab38f602c66c162c05e4b6ae0e2a7977ec2cdf"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 0F 6F D0 66 44 0F 6F C1 66 0F 69 E2 66 44 0F 61 D2 66 44 0F }

	condition:
		all of them
}
