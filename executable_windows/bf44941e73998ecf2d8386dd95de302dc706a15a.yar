rule win_matryoshka_rat_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.matryoshka_rat."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.matryoshka_rat"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b037 c3 b073 c3 }
		$sequence_1 = { c3 b06f c3 b063 c3 }
		$sequence_2 = { 8b46fc 8947fc 49 75ed 5f ff4210 }
		$sequence_3 = { 8b4704 ff4710 ff07 8b0488 }
		$sequence_4 = { 74e3 440fb603 430fbe841040d30500 85c0 }
		$sequence_5 = { 8b4708 3b470c 7507 8bcf }
		$sequence_6 = { 74e2 ff8170040000 83b97004000002 0f8493010000 83cfff 488d2d572c0300 }
		$sequence_7 = { 74e9 488d15b9450400 488bcb e8???????? }
		$sequence_8 = { 74de 83cbff 488bca e8???????? 90 48897c2420 }
		$sequence_9 = { 8b4708 b120 8b570c 8b7718 }
		$sequence_10 = { 74e6 488d152fac0300 488bcb e8???????? }
		$sequence_11 = { 8b4704 8b3491 890491 8bd6 }
		$sequence_12 = { 74e2 ff8170040000 83b97004000002 0f84eb010000 83cfff 4c8d3dde290300 }
		$sequence_13 = { 8b4704 8bf1 33d1 81e6ff030000 }

	condition:
		7 of them and filesize <843776
}