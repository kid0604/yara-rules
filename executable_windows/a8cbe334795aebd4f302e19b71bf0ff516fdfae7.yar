rule win_r980_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.r980."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.r980"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 51 8d4dd4 e8???????? 837de810 8d45d4 53 0f4345d4 }
		$sequence_1 = { e8???????? 56 8b08 8b01 ff5070 56 50 }
		$sequence_2 = { 8d4dbc e8???????? 8d4dd4 e8???????? 8d4da4 e8???????? 8b4df4 }
		$sequence_3 = { 85c0 7409 ff7608 50 e8???????? c7460800000000 c7460400000000 }
		$sequence_4 = { 50 e8???????? 8bce e8???????? 8b4d1c 83c418 }
		$sequence_5 = { 8bc7 f00fc14104 7515 8b01 ff10 8b4db4 8bc7 }
		$sequence_6 = { ff4654 837e5440 750c c7465400000000 e8???????? 8b4658 83f8f8 }
		$sequence_7 = { e8???????? 83ec18 8d8424c0000000 8bcc 50 e8???????? e9???????? }
		$sequence_8 = { 8bc8 e8???????? 33c9 894ddc 8b448dc8 0f57c0 41 }
		$sequence_9 = { c745fc00000000 8b30 8d45ec 50 e8???????? 83c404 8d4dec }

	condition:
		7 of them and filesize <3178496
}