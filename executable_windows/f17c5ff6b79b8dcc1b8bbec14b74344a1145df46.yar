rule win_cloud_duke_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.cloud_duke."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cloud_duke"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 33d2 84c0 8b44242c 0f44ca 83c618 83c718 }
		$sequence_1 = { ffb680000000 ffb424c8000000 ffb424c8000000 ff15???????? 85c0 }
		$sequence_2 = { e8???????? 51 8bc8 c645fc13 e8???????? 83c404 c645fc11 }
		$sequence_3 = { 6800280000 e8???????? 83c404 898680000000 85c0 0f849f020000 6800280000 }
		$sequence_4 = { 8d86a4010000 7202 8b00 50 8d842430070000 }
		$sequence_5 = { 0f84fb000000 6a0c 33c0 c745bc07000000 68???????? }
		$sequence_6 = { 742b 48 89442414 6aff 6a00 57 8bcb }
		$sequence_7 = { 85c0 0f8497000000 8b8c24b8000000 8b542420 }
		$sequence_8 = { 8a0430 46 88441de8 43 8975d8 83fb04 7574 }
		$sequence_9 = { 6806020000 50 668984241c010000 8d84241e010000 50 c744245c00000000 e8???????? }

	condition:
		7 of them and filesize <368640
}
