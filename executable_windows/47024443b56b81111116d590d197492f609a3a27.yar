rule win_bistromath_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.bistromath."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bistromath"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? 85c0 741d 0f57c0 0f1100 0f114010 660fd64020 }
		$sequence_1 = { ff75f0 56 e8???????? 8b45f8 83c40c c6040600 8bce }
		$sequence_2 = { eb24 8d5001 e8???????? 8bf0 85f6 7416 ff75fc }
		$sequence_3 = { e8???????? 8b4580 46 3bf0 7ce8 33f6 85db }
		$sequence_4 = { e8???????? 8b4c2410 8901 83c718 8b442424 83c104 894c2410 }
		$sequence_5 = { 8b45e8 85c0 0f84bb250000 ff474c 8d535f 8b7f4c 8bce }
		$sequence_6 = { e8???????? 8945e4 85c0 0f84e1010000 ff75f0 33d2 8bcb }
		$sequence_7 = { ff75fc e8???????? 8bf0 83c404 85f6 7418 8d45fc }
		$sequence_8 = { 8b4df8 e8???????? 8b5324 8b4df8 e8???????? 6a30 6a00 }
		$sequence_9 = { 83c404 46 8d7efe 83fe02 7304 33d2 eb2e }

	condition:
		7 of them and filesize <33816576
}