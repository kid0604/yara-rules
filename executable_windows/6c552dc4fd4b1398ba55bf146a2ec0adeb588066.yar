rule win_fobber_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.fobber."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.fobber"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 49 01cf 01ce 41 fd f3a4 fc }
		$sequence_1 = { 85c0 740f 89c1 8b450c fc f2ae 31c0 }
		$sequence_2 = { 57 8b7d08 57 e8???????? 85c0 740f 89c1 }
		$sequence_3 = { 89e5 6a00 ff750c ff7508 e8???????? }
		$sequence_4 = { 55 89e5 31c0 50 50 ff750c }
		$sequence_5 = { 3002 c0c803 0453 42 e2f6 59 }
		$sequence_6 = { fc f2ae f7d1 49 89c8 59 5f }
		$sequence_7 = { 89e5 51 8b4510 8b5508 8b4d0c 3002 }
		$sequence_8 = { 59 83f8ff 0f84a8ef0100 57 ff7510 }
		$sequence_9 = { 028736c8f07c 7d41 6f 01e9 339aa44cc9c2 c5fd594907 97 }
		$sequence_10 = { 5d c3 6a10 689014c072 e8???????? }
		$sequence_11 = { c083e841ff0520 57 c9 7283 }
		$sequence_12 = { 0f84a2840100 8b7d0c 3bfb 0f8697840100 8b5510 3bcb }
		$sequence_13 = { 81c78c4f0000 81c76c1c0000 81c7c6710000 81c7d32e0000 81c763130000 81ef035d0000 81ef431b0000 }
		$sequence_14 = { 55 8bec a1???????? 803840 ff750c 0f8423050000 }
		$sequence_15 = { 4f 3c23 b14b ba702bfeb4 61 }

	condition:
		7 of them and filesize <188416
}
