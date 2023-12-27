rule win_mariposa_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.mariposa."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mariposa"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 55 8bec 53 56 bb???????? 43 }
		$sequence_1 = { ffd3 33c0 50 e8???????? 33c0 }
		$sequence_2 = { 53 56 bb???????? 43 }
		$sequence_3 = { 885c0cff e2f1 ba???????? 2bd6 8bdc 03da 4b }
		$sequence_4 = { 8a1c0e 02d8 32dc fec0 885c0cff e2f1 }
		$sequence_5 = { 8bdc 03da 4b 54 ffd3 33c0 }
		$sequence_6 = { 885c0cff e2f1 ba???????? 2bd6 }
		$sequence_7 = { 8a4301 8a6302 f6d0 02c4 d0f8 8a1c0e }
		$sequence_8 = { 53 56 bb???????? 43 803b00 }
		$sequence_9 = { 03da 4b 54 ffd3 33c0 }

	condition:
		7 of them and filesize <311296
}