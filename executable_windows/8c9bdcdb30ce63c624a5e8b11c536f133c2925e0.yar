rule win_nagini_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nagini."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nagini"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 ff15???????? 8bf8 83ff09 7d3e 6a00 }
		$sequence_1 = { 48 7412 e8???????? c70016000000 e8???????? ebb4 c745e40c9a4200 }
		$sequence_2 = { e9???????? 8d442428 50 53 ff15???????? 6a65 ff35???????? }
		$sequence_3 = { 0904050904050c 0405 0c04 050c04050d }
		$sequence_4 = { 8935???????? 8b5004 a1???????? 8982cc8a4200 a1???????? 8b4004 834c301402 }
		$sequence_5 = { 2c63 40 005863 40 007c6340 0023 d18a0688078a }
		$sequence_6 = { 07 0505070505 0806 06 07 }
		$sequence_7 = { 83c602 eb33 58 668906 83c602 8b0c95c0914200 8a45f8 }
		$sequence_8 = { ff75e4 8b0485c0914200 ff3418 ff15???????? 85c0 7518 ff15???????? }
		$sequence_9 = { ff15???????? 68007f0000 6a00 8945cc c745d001000000 c745d400000000 c745d8c4384200 }

	condition:
		7 of them and filesize <12820480
}
