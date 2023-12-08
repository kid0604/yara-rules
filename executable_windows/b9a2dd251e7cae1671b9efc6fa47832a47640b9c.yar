rule win_calmthorn_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.calmthorn."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.calmthorn"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 8bf0 83feff 74c2 6a02 6a00 6a00 }
		$sequence_1 = { ebba 0fb68d2cfdffff 83f901 7552 c785a0c2ffff00000000 eb0f 8b95a0c2ffff }
		$sequence_2 = { ff7590 ff15???????? b801000000 5f 5e 5b 8b4dfc }
		$sequence_3 = { eb1e 8b850452ffff 83c001 8b8d0852ffff 83d100 89850452ffff 898d0852ffff }
		$sequence_4 = { ebba 0fb68d21fdffff 83f901 7553 0f57c0 660f13850c2fffff eb1e }
		$sequence_5 = { ebba 0fb6953ffdffff 83fa01 7556 0f57c0 660f1385d451ffff eb1e }
		$sequence_6 = { ebba 0fb69509fdffff 83fa01 7556 0f57c0 660f138574fdfeff eb1e }
		$sequence_7 = { ebba 0fb6952cfdffff 83fa01 7552 c7850cbfffff00000000 eb0f 8b850cbfffff }
		$sequence_8 = { eb02 ebba 0fb68d73fdffff 83f901 7553 0f57c0 660f1385947cffff }
		$sequence_9 = { ebb7 0fb69521fdffff 83fa01 7552 c785c8b8ffff00000000 eb0f 8b85c8b8ffff }

	condition:
		7 of them and filesize <2322432
}
