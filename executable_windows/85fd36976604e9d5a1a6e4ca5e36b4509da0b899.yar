rule win_chinotto_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.chinotto."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chinotto"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 034d0c 53 56 57 8b7848 8b774c }
		$sequence_1 = { 6a1a e8???????? 8bd8 b906000000 be???????? 8bfb f3a5 }
		$sequence_2 = { c745f800000000 8955c8 85d2 7505 ba02000000 8b461c 8bf8 }
		$sequence_3 = { 57 8945f0 8d5801 740e 8b4e1c 2b4e40 }
		$sequence_4 = { 837dfc00 7514 837dd000 0f8421080000 837e2000 0f8417080000 }
		$sequence_5 = { 8d8dd0fbffff 68???????? 51 ffd6 83c418 8d95a4f1ffff 52 }
		$sequence_6 = { 8b5620 57 8b7e24 8bc2 0bc7 7412 8bc2 }
		$sequence_7 = { 8a08 40 84c9 75f9 2bc7 8b7d18 }
		$sequence_8 = { 83c434 5f 5e 33cd 8d85e0fdfcff 5b }
		$sequence_9 = { 8b471c 50 0fafc1 034710 8d55f8 }

	condition:
		7 of them and filesize <300032
}