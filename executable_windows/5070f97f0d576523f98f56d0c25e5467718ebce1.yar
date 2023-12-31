rule win_goggles_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.goggles."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.goggles"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 53 ffd7 85c0 75c7 8b6c2418 56 }
		$sequence_1 = { ff15???????? 8b442410 8d4c241c 8d542420 }
		$sequence_2 = { 85c0 7430 68???????? ff15???????? 8d542408 52 }
		$sequence_3 = { 81fd90010000 f3ab aa 53 7616 ff15???????? }
		$sequence_4 = { 85c0 7443 8b2d???????? 8b442414 }
		$sequence_5 = { ffd3 57 6a04 8d44245c 6a01 50 ff15???????? }
		$sequence_6 = { 6a2f 56 ff15???????? 8bf8 83c9ff 47 }
		$sequence_7 = { c680a841001000 8d842410010000 6891010000 50 6a02 56 ffd5 }
		$sequence_8 = { 68???????? 51 68???????? e8???????? 83c410 c680a841001000 8d842410010000 }
		$sequence_9 = { ffd7 8d842484030000 682d010000 8d8c2484020000 50 51 e8???????? }

	condition:
		7 of them and filesize <57344
}
