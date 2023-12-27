rule win_enigma_loader_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.enigma_loader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.enigma_loader"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f86a9000000 ebbb 4885c0 740d 488bc8 e8???????? 488bd8 }
		$sequence_1 = { 48897010 408830 eb15 b918000000 e8???????? 48897010 48897008 }
		$sequence_2 = { 0fb7c0 6bc834 664103c8 41ffc0 66413109 4d8d4902 4183f80b }
		$sequence_3 = { 7644 8b4d00 8bd3 4803cf 488bc1 3819 7409 }
		$sequence_4 = { 90 41c6466801 4138b6b0000000 0f8559060000 bb00100000 488b5590 493bd5 }
		$sequence_5 = { 488bcb e8???????? 41894640 83f80c 0f858f020000 4088bd58020000 }
		$sequence_6 = { 448a4f14 0f839e000000 488d4101 48894310 4c397318 488bc3 7203 }
		$sequence_7 = { 4885db 740e 483bdf 0f84ac000000 e9???????? 4d8bb4f670b70200 33d2 }
		$sequence_8 = { e8???????? 48894620 488bcb e8???????? 41894640 83f80c }
		$sequence_9 = { 4c894018 4c894820 53 56 57 b840200000 e8???????? }

	condition:
		7 of them and filesize <798720
}