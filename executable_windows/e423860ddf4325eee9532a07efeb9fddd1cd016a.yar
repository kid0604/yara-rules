rule win_alphanc_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.alphanc."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.alphanc"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { bf???????? 8db574fdffff 33c0 f3a7 753c 6a01 6a01 }
		$sequence_1 = { 8d4630 c7869000000001000000 8906 e8???????? 894650 e8???????? 894644 }
		$sequence_2 = { f7d1 c1ea1f c1e91f 23d1 0be8 f7da 896c2420 }
		$sequence_3 = { f6c340 89442410 894c240c 751d 51 8d4e10 51 }
		$sequence_4 = { 8b8600010000 b901000000 f6c408 7550 8b5608 813a01030000 7f45 }
		$sequence_5 = { 5d 5b 81c47c010000 c3 5f 5e 5d }
		$sequence_6 = { e8???????? 56 68???????? 8d4c2444 6a10 51 e8???????? }
		$sequence_7 = { c744242400000000 f7e1 8b7c2424 8bda c1eb07 85ff 741b }
		$sequence_8 = { 8b4e20 894c2420 e8???????? 3bc5 894654 0f84a4070000 8b5608 }
		$sequence_9 = { c3 57 b925000000 33c0 8bfe f3ab 8d4630 }

	condition:
		7 of them and filesize <2015232
}
