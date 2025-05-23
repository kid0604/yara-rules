rule win_bubblewrap_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.bubblewrap."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bubblewrap"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bc8 83e103 f3a4 8d4c2418 51 55 e8???????? }
		$sequence_1 = { a1???????? 8b15???????? 83c404 f3a5 8b0d???????? a3???????? }
		$sequence_2 = { c3 b940000000 33c0 8dbc24a9000000 c68424a800000000 }
		$sequence_3 = { 750b 5f 5e 5d 5b 81c4a0ba0400 c3 }
		$sequence_4 = { 0bc2 49 79f0 89442458 33c0 }
		$sequence_5 = { 83c408 50 57 8b3d???????? ffd7 68???????? }
		$sequence_6 = { 5d 5b 81c4a0ba0400 c3 8b442410 8d4c2464 898424a4000000 }
		$sequence_7 = { 83c404 eb37 a1???????? 8b35???????? 50 ffd6 }
		$sequence_8 = { 0f8feffeffff 5b 8d4d02 b856555555 f7e9 8bc2 5f }
		$sequence_9 = { 33d2 89742414 8d6ced00 89542418 }

	condition:
		7 of them and filesize <57136
}
