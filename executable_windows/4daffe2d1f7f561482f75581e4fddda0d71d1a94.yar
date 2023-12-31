rule win_whiteblackcrypt_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.whiteblackcrypt."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.whiteblackcrypt"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 418a5305 41885309 418a5301 41884301 418a4302 41885305 }
		$sequence_1 = { 8801 48ffc1 ebe8 c3 55 57 56 }
		$sequence_2 = { e8???????? 0fb6c8 4189cf e8???????? }
		$sequence_3 = { dd5c2420 488b5c2420 4889d8 48c1e820 89c1 81e1ffffff7f 09d9 }
		$sequence_4 = { 99 f7f9 31c9 488d15eb3f0000 }
		$sequence_5 = { b905000000 4883c438 48ff25???????? 31c9 ff15???????? eb0b 4883c438 }
		$sequence_6 = { 0f854effffff 85c0 41b800050000 0f8440ffffff 66480f6eef }
		$sequence_7 = { 0f857ffcffff 85f6 7834 660f2ec7 7a06 0f846ffcffff }
		$sequence_8 = { ff15???????? 488d442478 4531c0 41b906000200 4889442420 }
		$sequence_9 = { 41b804010000 488d5728 4889f1 8903 488b442428 48894308 }

	condition:
		7 of them and filesize <99328
}
