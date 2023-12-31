rule win_catb_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.catb."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.catb"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 4a8b94e0403e0400 428a4cf23d f6c104 741b 428a44f23e 80e1fb }
		$sequence_1 = { eb1f be07000000 488d15ef9e0000 448bc6 488bcf e8???????? 85c0 }
		$sequence_2 = { 8bf9 488d15c7cf0000 b903000000 4c8d05b3cf0000 e8???????? }
		$sequence_3 = { eb07 488d3dc0ad0300 4883a4248000000000 4584f6 740b }
		$sequence_4 = { 4883ec40 488b05???????? 4833c4 4889442430 4533d2 4c8d1d776f0300 4d85c9 }
		$sequence_5 = { 4c8d0d6bab0300 4c8bc6 488bd7 488bcb e8???????? }
		$sequence_6 = { 488bd8 4885c0 0f84a1010000 33d2 }
		$sequence_7 = { 498bf8 8bf2 4c8d0d297e0000 488be9 }
		$sequence_8 = { 7410 4883f9ff 7406 ff15???????? 48832300 4883c308 488d0508ae0300 }
		$sequence_9 = { ebd3 488b442448 4883f8ff 74c8 488bd3 4c8d050e9c0300 83e23f }

	condition:
		7 of them and filesize <593920
}
