rule win_mpkbot_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.mpkbot."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mpkbot"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 8b45fc 3bc6 7406 8b08 50 ff5108 }
		$sequence_1 = { 56 56 68???????? 8975f4 8b08 50 ff510c }
		$sequence_2 = { 807e1100 7604 c6461100 57 }
		$sequence_3 = { a3???????? 8d45fc 50 683f000f00 6a00 }
		$sequence_4 = { 8b1d???????? ffd3 6a00 56 68???????? 68???????? }
		$sequence_5 = { ffe0 55 8bec 68???????? ff15???????? }
		$sequence_6 = { 6a18 5a 6689500e 33d2 }
		$sequence_7 = { c3 55 8bec 33c0 384508 7507 }
		$sequence_8 = { 50 68???????? 6a0d ff15???????? 8b35???????? eb14 8d45e4 }
		$sequence_9 = { 895010 895014 894818 89481c 895020 895024 }

	condition:
		7 of them and filesize <139264
}
