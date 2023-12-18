rule win_dmsniff_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.dmsniff."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dmsniff"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 83c661 89f3 881d???????? 8d04bf }
		$sequence_1 = { 50 d93c24 66810c240003 d92c24 83c404 6a00 6a00 }
		$sequence_2 = { 53 56 57 8b5d0c 8b7510 }
		$sequence_3 = { 89fe 46 89b5fcfeffff 899cbd00ffffff 8d85f0feffff 50 6a00 }
		$sequence_4 = { eb15 47 39f7 72d3 ff45fc 8b45f4 3945fc }
		$sequence_5 = { 56 57 8965e8 50 d93c24 }
		$sequence_6 = { eb18 68???????? e8???????? 50 68???????? e8???????? 83c40c }
		$sequence_7 = { e8???????? 50 68???????? e8???????? 83c40c eb18 }
		$sequence_8 = { e8???????? 83c40c eb18 68???????? e8???????? 50 }
		$sequence_9 = { 7316 8bbdfcfeffff 89fe 46 89b5fcfeffff 899cbd00ffffff }

	condition:
		7 of them and filesize <131072
}
