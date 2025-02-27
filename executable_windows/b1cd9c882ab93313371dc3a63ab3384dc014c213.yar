rule win_hawkball_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.hawkball."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hawkball"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d5f08 c745f000000000 8d470c c745ec0c000000 53 }
		$sequence_1 = { 51 53 8b1d???????? 8bd3 8bcb c1ea08 c1e910 }
		$sequence_2 = { e8???????? 83c40c 8d85fcfeffff 6a01 }
		$sequence_3 = { 81ec7c050000 53 56 8b7508 57 8b3e 85ff }
		$sequence_4 = { 53 660f6f05???????? 56 f30f7f4588 }
		$sequence_5 = { 6a01 894705 ff15???????? 50 }
		$sequence_6 = { 50 e8???????? 83c40c 8d842478020000 6a00 6a00 }
		$sequence_7 = { 83c40c 8d842478020000 6a00 6a00 6804010000 50 8d442464 }
		$sequence_8 = { 8b5dfc eb35 837e4400 7462 6a00 }
		$sequence_9 = { 6a08 ffd3 50 ff15???????? 8bf0 8d8578ffffff 50 }

	condition:
		7 of them and filesize <229376
}
