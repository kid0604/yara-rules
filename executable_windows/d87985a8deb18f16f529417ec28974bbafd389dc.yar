rule win_classfon_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.classfon."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.classfon"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a01 56 ffd0 85c0 7511 55 e8???????? }
		$sequence_1 = { 8d4c2400 c744240000000000 51 68???????? 52 c744241001000000 }
		$sequence_2 = { e8???????? 8b8c2420020000 8bb42418020000 8bd8 8bd1 8bfb }
		$sequence_3 = { 0f859d010000 8d4c241c 8d542424 51 8b4c2414 8d442424 52 }
		$sequence_4 = { 897d04 89450c 894508 894510 8b4b50 }
		$sequence_5 = { 83c408 40 8bf8 803f00 }
		$sequence_6 = { ffd3 89be00020000 89be10020000 89be14020000 5f 5e }
		$sequence_7 = { 03f5 56 89742418 ff15???????? 85c0 0f85c3000000 }
		$sequence_8 = { e8???????? 83c40c 85c0 7437 8b8c2428020000 }
		$sequence_9 = { 5f 5e 5b 81c418020000 c3 5f }

	condition:
		7 of them and filesize <73728
}
