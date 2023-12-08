rule win_acbackdoor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.acbackdoor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.acbackdoor"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b442448 89742404 89442408 a1???????? 891c24 ff5034 85c0 }
		$sequence_1 = { c744240410000000 890424 e8???????? 85c0 0f844c060000 893424 8944241c }
		$sequence_2 = { e8???????? 89c6 85c0 0f847f000000 8b842450020000 c744241000000000 c744240c00000000 }
		$sequence_3 = { 89442404 891c24 e8???????? 85c0 7426 c744240440000000 893424 }
		$sequence_4 = { ff15???????? 3b6c2410 75e3 8b542414 89d8 8b5c241c 85d2 }
		$sequence_5 = { 8bb424a0000000 83e20f 8d34d6 8b542428 8b86c0000000 337e44 83e20f }
		$sequence_6 = { ff15???????? e9???????? 81ff80400000 751a c7442408???????? 895c2404 893424 }
		$sequence_7 = { c7442458a4e14a00 c78424a400000000000000 e8???????? 8d8424b4000000 890424 e8???????? 8d8424c0000000 }
		$sequence_8 = { e9???????? ba80bfffff e9???????? baf0ffffff e9???????? 890424 e8???????? }
		$sequence_9 = { e9???????? dfabe00a0000 d835???????? 31c0 dd1a e9???????? dfabf80a0000 }

	condition:
		7 of them and filesize <1704960
}
