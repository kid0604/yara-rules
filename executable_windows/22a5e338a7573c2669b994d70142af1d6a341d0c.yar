rule win_racket_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.racket."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.racket"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 757b e8???????? 3906 7572 837e0c00 756c 8b4608 }
		$sequence_1 = { 7507 c74634f4af0510 6a00 57 8bce e8???????? 5f }
		$sequence_2 = { e8???????? 8b5590 8b4d8c 8bbd70ffffff 83c104 83ea01 894d8c }
		$sequence_3 = { e8???????? 83c40c 8d8ddcfaffff 68???????? e8???????? 6804010000 8d85e0fbffff }
		$sequence_4 = { 8b9568ffffff 8b4214 394218 7420 8b4dac 8908 c7400400000000 }
		$sequence_5 = { 50 e8???????? 6a00 8d8558f6ffff 50 6aff 8d855cf6ffff }
		$sequence_6 = { 8b4da4 eb03 8b45e0 837dc400 893488 745c 8b45f4 }
		$sequence_7 = { 660f56c3 660f58e0 660fc5c400 25f0070000 660f28a050f70510 660f28b840f30510 660f54f0 }
		$sequence_8 = { 56 e8???????? e8???????? 6a00 ffb5c8feffff 56 e8???????? }
		$sequence_9 = { 8bd0 8b37 2bd6 8b4d0c 8945e0 b8ffa16f6b f7ea }

	condition:
		7 of them and filesize <985088
}
