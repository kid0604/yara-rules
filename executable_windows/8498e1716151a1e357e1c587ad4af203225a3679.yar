rule win_unidentified_078_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.unidentified_078."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_078"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3c18 0f8483000000 3c1c 740d }
		$sequence_1 = { ffd0 ebc9 ffd0 ebc5 }
		$sequence_2 = { 80fa0d 0f8421010000 80fa1b 0f8576010000 ba02000000 e8???????? }
		$sequence_3 = { 0f84ca000000 0f8fe5000000 80fa07 0f85b8010000 ba02000000 }
		$sequence_4 = { 771b 3c10 0f8406020000 0f87bb010000 }
		$sequence_5 = { e9???????? 80fa0c 0f8412010000 0f8cee000000 80fa0d }
		$sequence_6 = { 0f8f8f000000 80fa20 0f8d28020000 80fa0a 0f8417010000 7f39 80fa08 }
		$sequence_7 = { e8???????? 84c0 7467 f60701 7562 }
		$sequence_8 = { 8a44010f 3c5c 7419 3c2f 7415 }
		$sequence_9 = { 3c1c 740d 3c16 0f855a020000 }

	condition:
		7 of them and filesize <688128
}