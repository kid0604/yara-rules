rule win_regin_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.regin."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.regin"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 49 8363f000 48 8d0504230000 49 8943d8 }
		$sequence_1 = { 48 89442438 b800210000 c7442430204e0000 89442428 }
		$sequence_2 = { 85c0 740c 8b05???????? 39442460 7405 }
		$sequence_3 = { c1e802 41 ffc0 48 8d4c2470 41 }
		$sequence_4 = { 44 8bc1 48 8b0d???????? ff15???????? }
		$sequence_5 = { 48 89442448 48 89442450 b82375f1ba }
		$sequence_6 = { 33c0 48 83c428 c3 48 83ec28 33c9 }
		$sequence_7 = { 0f45df 8bc3 48 8b5c2448 }
		$sequence_8 = { 84c0 44 8d7304 0f45f8 8d4302 44 84c0 }
		$sequence_9 = { 48 8bfb 8bc7 48 8b5c2430 48 }

	condition:
		7 of them and filesize <49152
}
