rule win_gemcutter_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.gemcutter."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gemcutter"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { fec8 8886a0314000 8a843579ffffff 46 ebea 395d08 889ea0314000 }
		$sequence_1 = { 8d85f0fcffff 53 50 ffd6 8d85f0fcffff }
		$sequence_2 = { 68???????? e8???????? 83c424 8b3d???????? 56 }
		$sequence_3 = { 6a01 ff15???????? 6a01 68???????? e8???????? 6a01 }
		$sequence_4 = { e8???????? 83c424 8b3d???????? 56 33f6 }
		$sequence_5 = { 83c410 8d85f0fdffff 53 50 ffd6 8b3d???????? 8d85f0fdffff }
		$sequence_6 = { 57 53 6801001f00 ff15???????? 3bc3 be???????? }
		$sequence_7 = { 56 ff15???????? 8bf8 8d8500fcffff }
		$sequence_8 = { fec8 8886a0314000 8a843579ffffff 46 ebea 395d08 }
		$sequence_9 = { 6a00 6801001f00 ff15???????? 85c0 7517 68e8030000 ff15???????? }

	condition:
		7 of them and filesize <40960
}
