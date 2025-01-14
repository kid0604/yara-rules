rule win_maktub_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.maktub."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.maktub"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ffd0 f7d8 1bc0 f7d8 8be5 }
		$sequence_1 = { ff7508 ffd0 85c0 0f846bffffff }
		$sequence_2 = { ff15???????? c74604???????? c70601000000 eb02 33f6 8b0d???????? }
		$sequence_3 = { c7430800000000 c7430c00000000 85f6 7428 a1???????? 8b3e 85c0 }
		$sequence_4 = { ff15???????? c74604???????? c70602000000 eb02 }
		$sequence_5 = { ff15???????? e9???????? 6a00 8d45f8 c745f800000000 }
		$sequence_6 = { ff15???????? e9???????? 51 8bdc }
		$sequence_7 = { c7430800000000 c7430c00000000 c7430400000000 c70300000000 }
		$sequence_8 = { ff30 e8???????? 8bc7 5f 5e 5b }
		$sequence_9 = { 8d4e48 e8???????? 6a05 8bce e8???????? 5f }
		$sequence_10 = { c7461407000000 33c0 668906 5e c20800 b8???????? e8???????? }
		$sequence_11 = { 8d4e48 e8???????? 8d4e34 e8???????? 8d4e08 }
		$sequence_12 = { 8d4e50 e8???????? 8bc6 5e }
		$sequence_13 = { 8d4e50 e8???????? 8d4e40 e8???????? 8d4e30 e8???????? 8d4e1c }
		$sequence_14 = { c7463464204d00 c7463806000000 c6463c00 5f }
		$sequence_15 = { c7463464204d00 57 ff7634 e8???????? }
		$sequence_16 = { 8d4e68 e8???????? 83a6b400000000 8d8eb8000000 }
		$sequence_17 = { c7461c00000000 85db 741a 68b4000000 }
		$sequence_18 = { 8d4e48 e8???????? 814e0400000080 8bc6 }
		$sequence_19 = { c7463464204d00 6a00 57 8bce }
		$sequence_20 = { c746140f000000 c60600 5e c20800 8b542404 }
		$sequence_21 = { 8d4e50 e8???????? 8d4df0 e8???????? }

	condition:
		7 of them and filesize <3063808
}
