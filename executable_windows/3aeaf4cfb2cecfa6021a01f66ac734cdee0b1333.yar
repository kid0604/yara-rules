import "pe"

rule TrainerCreationKitv5Trainer
{
	meta:
		author = "malware-lu"
		description = "Detects TrainerCreationKitv5 Trainer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 00 68 80 00 00 00 6A 02 6A 00 6A 00 68 00 00 00 40 68 25 45 40 00 E8 3C 02 00 00 50 6A 00 68 40 45 40 00 68 00 10 00 00 68 00 30 40 00 50 E8 54 02 00 00 58 50 E8 17 02 00 00 6A 00 E8 2E 02 00 00 A3 70 45 40 00 68 25 45 40 00 E8 2B 02 00 00 A3 30 45 40 }

	condition:
		$a0
}
