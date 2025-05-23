rule win_unidentified_042_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.unidentified_042."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.unidentified_042"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 6a20 ba???????? 8bde e8???????? 83c404 85c0 7410 }
		$sequence_1 = { 52 8b9578ffffff 50 53 8d8d7cffffff e8???????? 83c414 }
		$sequence_2 = { 33f7 8b7df0 337dec 23f8 337df0 03f7 8bbdd8feffff }
		$sequence_3 = { e8???????? 83c408 85c0 7809 7e07 03f0 83fe04 }
		$sequence_4 = { 0bfa 48 75f1 eb03 0fb6f8 }
		$sequence_5 = { 25efff0000 66c1e104 660bc8 66898b50020000 8a4648 2401 0fb6c0 }
		$sequence_6 = { c7855cfaffff25da3f2e c78560fafffffafe28be c78564faffffaff05b42 c78568faffff0973699c c7856cfaffffb195ef80 c78570faffffdccc6129 c78574faffff2b44064a }
		$sequence_7 = { 1bc0 2556ffffff 33cd 83c011 e8???????? 8be5 }
		$sequence_8 = { 8b7df4 8b45e8 83f903 0f8dad000000 85c9 0f88a5000000 8bd1 }
		$sequence_9 = { 6824a4e360 681c781e53 6890000000 6a01 6a02 e8???????? 8b4df8 }

	condition:
		7 of them and filesize <516096
}
