rule win_absentloader_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.absentloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.absentloader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { fe81b89406fd 89148d909406fd 8d4dfc e8???????? 5e c9 c3 }
		$sequence_1 = { eb16 66c704375c6e eb0e 66c704375c74 eb06 66c704375c62 83c602 }
		$sequence_2 = { e8???????? c645fc12 8bcb 0f2805???????? 0f1145b4 6a7f }
		$sequence_3 = { 740f 33c0 80b034a606fd2e 40 83f814 72f3 8b0d???????? }
		$sequence_4 = { 8bec 56 ff7508 8bf1 e8???????? c706841e05fd }
		$sequence_5 = { 7408 3a8ac05d05fd 755a 8b06 8a08 40 42 }
		$sequence_6 = { 7e37 68f8aa06fd e8???????? 833d????????ff 59 7523 bffcaa06fd }
		$sequence_7 = { 7417 6827130000 6830f405fd 68341606fd e8???????? 83c40c 837f2c00 }
		$sequence_8 = { c9 c3 6a08 b8a30305fd e8???????? 8bf1 8975ec }
		$sequence_9 = { 84db 743b 8b4608 8378fc00 7432 83ec10 8d4668 }

	condition:
		7 of them and filesize <794624
}
