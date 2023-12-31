rule win_dramnudge_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.dramnudge."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.dramnudge"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 014218 eb18 03c3 8bd3 }
		$sequence_1 = { 000c00 20b140005f5f 7277 7374 }
		$sequence_2 = { 014318 8b430c 2b4308 03c6 }
		$sequence_3 = { 000c00 e0d9 40 007374 }
		$sequence_4 = { 014318 8b4318 8b55f8 03d6 }
		$sequence_5 = { 007374 643a3a 7275 6e }
		$sequence_6 = { 0000 90 000c00 20b140005f5f }
		$sequence_7 = { 014318 eb5b 33f6 eb01 }

	condition:
		7 of them and filesize <1294336
}
