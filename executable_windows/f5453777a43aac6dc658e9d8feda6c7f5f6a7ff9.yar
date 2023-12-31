rule win_locky_decryptor_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.locky_decryptor."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.locky_decryptor"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 740f 837decff 7409 ff75ec ff15???????? f68518feffff01 895dec }
		$sequence_1 = { 4b 395c2414 7cc8 85c0 741b 6bc01c 6a03 }
		$sequence_2 = { 5d c20800 55 8bec 837d0c01 8b4508 }
		$sequence_3 = { 8d45ec 50 8d850cfbffff 50 33f6 56 56 }
		$sequence_4 = { 8d45f8 668b00 668945f8 8d45d2 663b75d2 7c03 }
		$sequence_5 = { d1fe 89742418 895c2414 8d442414 3bde }
		$sequence_6 = { 50 e8???????? 33c0 c785e0fefffffc6b4100 8dbdf0feffff ab ab }
		$sequence_7 = { 895dfc e8???????? 50 8d45cc 50 8b4508 e8???????? }
		$sequence_8 = { e8???????? c9 c20c00 55 8bec 83ec14 8b4510 }
		$sequence_9 = { 8d442418 e8???????? 3bc6 741e 6821170000 8d442418 }

	condition:
		7 of them and filesize <278528
}
