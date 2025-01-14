rule win_mailto_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.mailto."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mailto"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bc8 83c408 85c9 7412 a1???????? }
		$sequence_1 = { 8d8424d4000000 50 8d442440 50 e8???????? 8d442444 50 }
		$sequence_2 = { c744246072006900 c744246476006900 c74424686c006500 c744246c67006500 6689442470 6a10 }
		$sequence_3 = { 8b4c241c 660f1f840000000000 8bc3 81e3ffffff03 c1f81a 0344242c }
		$sequence_4 = { 83f804 57 0f44d9 e8???????? 83c404 85db 747d }
		$sequence_5 = { 56 8b742428 56 8b4034 ffd0 83c408 85c0 }
		$sequence_6 = { 2b442410 83c003 50 e8???????? 83c404 89442410 85c0 }
		$sequence_7 = { 53 55 56 8b742420 33db 85f6 0f84a0000000 }
		$sequence_8 = { e8???????? 83c40c c7400c00000000 8d4705 5f }
		$sequence_9 = { 53 8b2cb0 e8???????? 50 53 ff7504 e8???????? }

	condition:
		7 of them and filesize <180224
}
