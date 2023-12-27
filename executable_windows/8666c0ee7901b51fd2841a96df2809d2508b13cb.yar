rule win_varenyky_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.varenyky."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.varenyky"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 59 40 00b859400023 d18a0688078a }
		$sequence_1 = { 030cb5401efd00 eb02 8bca f641247f 7591 83f8ff 7419 }
		$sequence_2 = { 8d8c2454010000 68???????? 51 e8???????? 8d84245c010000 83c40c }
		$sequence_3 = { 50 668954240c ff15???????? 6a10 }
		$sequence_4 = { e8???????? 8bc6 c1f805 8b0485401efd00 83e61f c1e606 59 }
		$sequence_5 = { 56 e8???????? 59 8945e4 8b7508 c7465c98c84000 33ff }
		$sequence_6 = { 6803010000 8d84249d010000 6a00 50 e8???????? }
		$sequence_7 = { 85c0 0f8e13010000 6887130000 8d542435 6a00 52 c644243c00 }
		$sequence_8 = { 0fbe8030c24000 83e00f 33f6 eb04 33f6 33c0 0fbe84c150c24000 }
		$sequence_9 = { 57 ffd3 85c0 0f847e000000 57 }

	condition:
		7 of them and filesize <24846336
}