rule win_shareip_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.shareip."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.shareip"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8a542417 8a042f 0fbec8 83e920 0f841a010000 83e902 0f848c000000 }
		$sequence_1 = { 8d442410 50 53 6a00 6a00 68???????? bf20000000 }
		$sequence_2 = { 059979825a 03d0 8bc7 c1c20d 33c6 8b29 33c2 }
		$sequence_3 = { e8???????? 6a01 c645fc03 8b4814 68???????? 51 6a00 }
		$sequence_4 = { 57 52 50 894638 e8???????? 83c410 8bc6 }
		$sequence_5 = { 8b85d0000000 3bc6 740f 50 e8???????? 83c404 89b5d0000000 }
		$sequence_6 = { 83e3fc 83c318 c7841c28010000ffffffff 83c308 0fb6c3 50 885e1e }
		$sequence_7 = { 750c c745ec04000000 e9???????? 8b0b 8b4904 8d45e0 }
		$sequence_8 = { bf01000000 e8???????? 8bd0 8bcb e8???????? 85c0 }
		$sequence_9 = { 7410 8b542434 8b02 8d4c2434 ffd0 8b44243c 396c2440 }

	condition:
		7 of them and filesize <811008
}
