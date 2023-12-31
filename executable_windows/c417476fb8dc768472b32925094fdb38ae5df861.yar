rule win_carrotbat_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.carrotbat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.carrotbat"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b7c2404 66c1c60c 8b742408 f6d7 33cd f7d3 }
		$sequence_1 = { 8f442434 51 887c2404 66890424 890424 }
		$sequence_2 = { 8b0c8d20ee4000 8d440104 8020fe ff36 e8???????? 59 }
		$sequence_3 = { c3 8bff 56 57 33f6 bf???????? 833cf5a4d5400001 }
		$sequence_4 = { 8b0c8d20ee4000 c1e006 8d440104 8020fe ff36 }
		$sequence_5 = { c1f805 8d3c8520ee4000 8bf3 83e61f c1e606 8b07 0fbe440604 }
		$sequence_6 = { 888c05f4fdffff 40 84c9 75ed 8d85f8feffff 6a5c }
		$sequence_7 = { 50 66a5 ff15???????? 6810270000 ff15???????? }
		$sequence_8 = { 5b c21000 ff25???????? c705????????6ca14000 }
		$sequence_9 = { 8f442434 9c 57 ff74243c c24000 686d3f4f6e }

	condition:
		7 of them and filesize <360448
}
