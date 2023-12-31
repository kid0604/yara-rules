rule win_hermeticwizard_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.hermeticwizard."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hermeticwizard"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33ff 837d0c00 744b 53 ff750c ff15???????? }
		$sequence_1 = { 894de0 ff15???????? f7d8 1ac0 fec0 5f }
		$sequence_2 = { 7415 668b5902 663b5f02 750f }
		$sequence_3 = { 8b450c 0fb684c8c05d0110 c1e804 5d c20800 }
		$sequence_4 = { 8bcf 50 e8???????? eb61 8d45e8 8bce }
		$sequence_5 = { 6bc930 53 56 8b0485c0dd0110 33db 8b7508 }
		$sequence_6 = { 0f84d3000000 8b048dc47c0110 89859cf8ffff 85c0 0f8498000000 }
		$sequence_7 = { 66894584 33c0 66894586 8d856cffffff 50 6689957affffff }
		$sequence_8 = { 750c 8b4d08 8d4708 50 e8???????? 8b3f }
		$sequence_9 = { 8bd1 8d7de4 59 33c0 }

	condition:
		7 of them and filesize <263168
}
