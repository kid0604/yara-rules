rule win_juicy_potato_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.juicy_potato."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.juicy_potato"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 488bcb e8???????? 837b1000 7514 488d05f7cb0300 483bd8 }
		$sequence_1 = { 488905???????? ff15???????? 488bc8 488d152e9c0100 }
		$sequence_2 = { 488bd9 488bc2 488d0d05950100 48890b }
		$sequence_3 = { 4d8be1 33c0 498be8 4c8d0d8b6effff 4c8bea }
		$sequence_4 = { 488d0de1970100 ff15???????? 488bc8 488d1541180100 ff15???????? }
		$sequence_5 = { 488d05763c0300 4889442450 b801000000 8705???????? }
		$sequence_6 = { 4585e4 0f88be040000 41f7e4 8bc2 488d1528c1feff c1e803 89442448 }
		$sequence_7 = { eb1e f20f1005???????? f20f118530010000 0fb705???????? 66898538010000 488b15???????? 4885d2 }
		$sequence_8 = { 488bd9 488bc2 488d0dad400300 48890b 488d5308 33c9 48890a }
		$sequence_9 = { 8b81d0000000 85c0 750d 488b8d98000000 e8???????? 90 488d0578a5ffff }

	condition:
		7 of them and filesize <736256
}
