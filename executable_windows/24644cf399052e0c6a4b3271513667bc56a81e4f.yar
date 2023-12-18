rule win_parallax_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.parallax."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parallax"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8dbf8c000000 b934000000 f3a4 5e 56 ff7508 }
		$sequence_1 = { ff7508 ff9698010000 5e 5d c21400 55 8bec }
		$sequence_2 = { 8b5234 83c234 8915???????? 83be1801000000 7545 83be1801000000 7401 }
		$sequence_3 = { ff763c 683c800000 ff35???????? ff92e0010000 6a00 }
		$sequence_4 = { 7411 8b75ec 8b7de0 8b4de8 f3a4 }
		$sequence_5 = { 85c0 7418 8bf8 8b35???????? b8ffffffff f0874704 50 }
		$sequence_6 = { 6a00 ff9628010000 6a04 68???????? }
		$sequence_7 = { e9???????? 3d34800000 750d ff7514 ff7510 e8???????? eb6d }
		$sequence_8 = { 8b5634 83c234 52 52 }
		$sequence_9 = { 83e934 8b4734 83c034 8b15???????? 50 51 ff92dc000000 }

	condition:
		7 of them and filesize <352256
}
