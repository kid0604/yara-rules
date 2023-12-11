rule win_tokyox_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.tokyox."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.tokyox"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4304 6800000008 894588 8b06 }
		$sequence_1 = { e8???????? 83c404 8bc8 ff35???????? 68???????? }
		$sequence_2 = { 68e9fd0000 ff15???????? 8b4d0c 8b45f8 }
		$sequence_3 = { 8dbdecefffff 037d10 897df4 8d1c02 8bc6 }
		$sequence_4 = { ff36 ffd7 ff730c ffd7 }
		$sequence_5 = { 66890471 33c0 66890451 eb56 6a01 c645c000 68???????? }
		$sequence_6 = { 6685c0 75e8 8d9554ffffff 8bf2 668b02 83c202 6685c0 }
		$sequence_7 = { 7543 8b4608 8b3d???????? 85c0 740a 50 ffd7 }
		$sequence_8 = { 0f1f4000 8b45f4 85c0 7474 6a00 }
		$sequence_9 = { 33c0 66890451 e9???????? 6a01 c645d000 68???????? }

	condition:
		7 of them and filesize <237568
}
