rule win_rektloader_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.rektloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rektloader"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0fbe02 8b4d24 2bc8 894d24 0fb655af 52 6a01 }
		$sequence_1 = { c1f906 8b5508 83e23f 6bc238 03048d08ab5600 b901000000 d1e1 }
		$sequence_2 = { 89459c c745fcffffffff 8d4d84 e8???????? 6a30 8b4d9c e8???????? }
		$sequence_3 = { 33c0 8845ef 0fb64def 51 8b5508 52 }
		$sequence_4 = { 854a00 40 854a00 40 854a00 2f }
		$sequence_5 = { 3b10 7427 8b4508 81784ca0725600 741b 8b4d08 8b514c }
		$sequence_6 = { e8???????? 83c418 83f801 7501 cc 6a00 683e020000 }
		$sequence_7 = { 837d1000 740b 8b4d10 898dc47fffff eb0a c785c47fffff3cc05400 8b95c47fffff }
		$sequence_8 = { 51 8b55cc 52 e8???????? 83c404 50 8b45d0 }
		$sequence_9 = { 83c408 8945f4 837df400 7515 660fb645ff 8b4d08 668901 }

	condition:
		7 of them and filesize <3080192
}
