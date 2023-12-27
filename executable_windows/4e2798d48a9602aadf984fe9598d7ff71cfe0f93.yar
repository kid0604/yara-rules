rule win_rokku_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.rokku."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rokku"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f2805???????? 0f114561 8ac1 028541ffffff 30840d42ffffff }
		$sequence_1 = { 8bc1 8b942444000300 0bc2 0f8456020000 6a06 }
		$sequence_2 = { 8d141b f7ea 8bf8 8bda 8bc1 f76c2470 03f8 }
		$sequence_3 = { 89442438 8b44246c 89442418 8b442468 89442414 8b442464 89442444 }
		$sequence_4 = { 8b0e e8???????? 33c9 84c0 0f454d08 890e eb1f }
		$sequence_5 = { c706???????? 8365fc00 8b4e04 85c9 740d 8b01 ff5010 }
		$sequence_6 = { 13ea f76c2454 896c2420 01442410 8d0436 8b742460 }
		$sequence_7 = { 8b7a18 8b5220 337918 335120 23fd 8b4824 23d5 }
		$sequence_8 = { 894d10 8b4c2414 0fa4c119 8b4c2468 c1e019 2bf0 8bc7 }
		$sequence_9 = { 55 56 57 898c24ac000000 8b02 89442454 8b4204 }

	condition:
		7 of them and filesize <548864
}