rule win_darkcloud_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.darkcloud."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkcloud"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c414 8d4db0 ff15???????? c745fc23000000 8b4d08 894da8 }
		$sequence_1 = { 894598 894db0 8945a8 894dc0 8945b8 ff15???????? 50 }
		$sequence_2 = { 6a00 51 8bf0 ff15???????? 50 56 6a00 }
		$sequence_3 = { 8d8d68ffffff 51 ff15???????? c745fc06000000 ba???????? 8d4dcc ff15???????? }
		$sequence_4 = { 8d855cffffff 8d8df8feffff 50 8d954cffffff 51 52 c7851cffffff08000000 }
		$sequence_5 = { 668b55dc 663b954cffffff 0f8ff4000000 c745fc0c000000 8d45dc 894584 c7857cffffff02400000 }
		$sequence_6 = { ff15???????? 8bd0 8d8df0feffff ff15???????? 50 8b559c 52 }
		$sequence_7 = { 668b00 8975dc 662d0100 8975cc 0f80e4000000 8975ac 894584 }
		$sequence_8 = { 50 8d4d94 51 e8???????? 8bd0 8d4d84 ff15???????? }
		$sequence_9 = { ff15???????? 8bd0 8d4da8 ff15???????? 8d5588 52 8d458c }

	condition:
		7 of them and filesize <622592
}
