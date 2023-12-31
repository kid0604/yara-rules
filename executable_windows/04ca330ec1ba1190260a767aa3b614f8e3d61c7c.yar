rule win_unidentified_098_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.unidentified_098."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_098"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4c89c3 4989cc 488931 4c8b12 4d8d0442 4c89d2 e8???????? }
		$sequence_1 = { 488b8c2488000000 48894c2428 0fbe8c2480000000 894c2420 4c89e1 ff5010 4c89e0 }
		$sequence_2 = { 488b4500 488d7e10 48c7430800000000 488906 488b40e8 48897c2420 48891406 }
		$sequence_3 = { e8???????? 4d85e4 740d 4c89e1 e8???????? e8???????? 488b4f08 }
		$sequence_4 = { 8903 488b742420 4883c304 483b742428 0f8494000000 4839df 0f84b9000000 }
		$sequence_5 = { 88450a 4c896b10 488b4c2458 48897328 4c897b38 4c897348 c6436f01 }
		$sequence_6 = { 4c89d2 e8???????? 488903 4883c430 5b c3 4989c9 }
		$sequence_7 = { 4c89fa 89c1 4429f9 4084ff 0f8549ffffff 41f7c200020000 0f843cffffff }
		$sequence_8 = { 8944242c 498b0424 488b40e8 4d8bac04e8000000 498b6d18 4d8b7d10 4889e9 }
		$sequence_9 = { e8???????? 418b442414 83f80a 7580 0f1f00 49ff442430 49c744242800000000 }

	condition:
		7 of them and filesize <3345408
}
