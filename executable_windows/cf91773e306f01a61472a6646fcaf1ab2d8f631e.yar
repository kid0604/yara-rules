rule win_helminth_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.helminth."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.helminth"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { a1???????? 68e8030000 8907 e8???????? }
		$sequence_1 = { 83e61f c1e606 57 8b3c9d70750110 8a4c3704 }
		$sequence_2 = { 894c2408 8d9b00000000 668b02 83c202 6685c0 }
		$sequence_3 = { c1e106 899528e5ffff 53 8b149570750110 898d24e5ffff 8a5c1124 02db }
		$sequence_4 = { 85ff 0f84be000000 897de0 8b049d70750110 0500080000 3bf8 }
		$sequence_5 = { 03f2 eb5c 8b45f4 8b0c8570750110 f644190448 }
		$sequence_6 = { 80c980 884c3704 8b0c9d70750110 8a443124 2481 }
		$sequence_7 = { 2c2c 2c2c 232425???????? 2c2c 2c2c 2c2c }
		$sequence_8 = { e8???????? 59 6a64 ff15???????? 57 57 }
		$sequence_9 = { 8bf9 897c2410 e8???????? 8bcf }
		$sequence_10 = { 8a02 8b9524e5ffff 8b0c9d28eb4100 88440a34 8b049d28eb4100 c744023801000000 }
		$sequence_11 = { 663bc1 75f4 6a18 59 be???????? }
		$sequence_12 = { a1???????? eb0c c745e4a4ee4100 a1???????? 33db }
		$sequence_13 = { 83c102 663bc3 75f4 a1???????? 8bd7 }
		$sequence_14 = { 6a03 68???????? 8d0c458ce44100 8bc1 2d???????? d1f8 }

	condition:
		7 of them and filesize <479232
}
