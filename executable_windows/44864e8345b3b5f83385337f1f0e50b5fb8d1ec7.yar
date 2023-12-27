rule win_joanap_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.joanap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.joanap"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7cda 8bc7 5f ddd8 5e c3 5f }
		$sequence_1 = { f2ae f7d1 49 03eb 8d7c2906 83c9ff f2ae }
		$sequence_2 = { 51 56 c7803c05000001000000 e8???????? 83c414 83f8ff 7440 }
		$sequence_3 = { c3 8b5c2414 50 ff15???????? 5f 5e 8bc3 }
		$sequence_4 = { 8b44241c 50 ff15???????? 8b442420 5b 85c0 750e }
		$sequence_5 = { ff15???????? 8b4c2410 6a01 6860ea0000 8d9424a0000000 }
		$sequence_6 = { 6683780400 7422 8b0d???????? 8b10 8911 8b5004 895104 }
		$sequence_7 = { 52 56 ffd7 85c0 a3???????? 7533 8d8c2408010000 }
		$sequence_8 = { e8???????? 6a04 6a00 68???????? 8d542440 68???????? 52 }
		$sequence_9 = { 55 8bec 83ec4c 56 8d45f0 57 50 }

	condition:
		7 of them and filesize <270336
}