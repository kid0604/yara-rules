rule win_marap_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.marap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.marap"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8386e41d000002 e9???????? 8386e41d000003 }
		$sequence_1 = { 7409 8386e41d000008 eb2f 84c0 7908 018ee41d0000 }
		$sequence_2 = { ff15???????? 8bf0 89b59cfbffff 83feff 7472 }
		$sequence_3 = { ff15???????? 85c0 7425 8b480c 8b11 8b02 }
		$sequence_4 = { 81fb00040000 737e 8bc7 8bd7 668b08 }
		$sequence_5 = { 0fbe84c1f8cb0010 6a07 c1f804 59 }
		$sequence_6 = { 83c40c 8d7bfe 668b4702 83c702 6685c0 75f4 }
		$sequence_7 = { 8d1c8580320110 8b03 83e71f c1e706 8a4c3824 }
		$sequence_8 = { 8d4310 8d8954f40010 5a 668b31 }
		$sequence_9 = { 80f901 0f8487000000 6683fa06 7519 84c0 }

	condition:
		7 of them and filesize <188416
}
