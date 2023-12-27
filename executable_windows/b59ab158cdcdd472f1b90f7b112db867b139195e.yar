rule win_milum_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.milum."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.milum"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8db53cffffff e8???????? 83c41c c645fc20 50 8d4d90 e8???????? }
		$sequence_1 = { 837b1800 0f8507010000 8b45f0 50 8d75dc e8???????? 837b1800 }
		$sequence_2 = { 50 e8???????? 8bc6 eb0f 885dfc 8d8d34ffffff }
		$sequence_3 = { 8b4dcc 8b55c8 83c40c c78574ffffff44000000 8945ac 894db4 814da001010000 }
		$sequence_4 = { 8d8d10feffff e8???????? c645fc1e 8d8df4fdffff e8???????? c645fc1d }
		$sequence_5 = { 2bc6 c7421803000000 89421c 395a18 0f849cfeffff ddd8 ddd8 }
		$sequence_6 = { 6bc064 2bc8 8d045590a64600 0fb610 8816 0fb64001 884601 }
		$sequence_7 = { 385f45 7503 895704 8b7a04 897e04 8b7804 3b5704 }
		$sequence_8 = { 8bca eb0e 8b55e8 2bd1 8b4e44 8955d4 894ddc }
		$sequence_9 = { 8d7508 83ec1c 8bcc 8bc6 c741140f000000 895910 896598 }

	condition:
		7 of them and filesize <1076224
}