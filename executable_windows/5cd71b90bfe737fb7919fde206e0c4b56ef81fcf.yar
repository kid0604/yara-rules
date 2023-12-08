rule win_chewbacca_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.chewbacca."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.chewbacca"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? c70424???????? e8???????? c7442414b02e6800 c744241024356800 c744240cc9000000 89442408 }
		$sequence_1 = { eb23 8d7600 8dbc2700000000 89f3 8b33 8b4304 890424 }
		$sequence_2 = { a1???????? 83c040 890424 e8???????? e8???????? 85ed 0f8591000000 }
		$sequence_3 = { ff530c 891c24 e8???????? 85f6 75e7 c70700000000 83c410 }
		$sequence_4 = { ff448500 ff442428 8b1b 833b00 753f 8b0d???????? 8b4304 }
		$sequence_5 = { eb3d 8b5608 89d8 e8???????? eb31 8b4608 8b10 }
		$sequence_6 = { e8???????? e9???????? 837b0800 0f84b9010000 668b03 6625ff0f 663d0200 }
		$sequence_7 = { e9???????? 8b54242c 0fb602 83e827 89442428 8b442444 8b542428 }
		$sequence_8 = { e8???????? c7460800000000 85f6 7408 893424 e8???????? ff442414 }
		$sequence_9 = { e8???????? 8d8578ffffff e8???????? 8d45c8 e8???????? 58 85c0 }

	condition:
		7 of them and filesize <9764864
}
