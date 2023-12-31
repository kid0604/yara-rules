rule win_pitou_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.pitou."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pitou"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8bda c1e305 03c3 8bda }
		$sequence_1 = { ac 8bda c1e305 03c3 8bda c1eb02 03c3 }
		$sequence_2 = { c1e305 03c3 8bda c1eb02 }
		$sequence_3 = { 8a6201 80f457 8acc 80e103 }
		$sequence_4 = { 8bda c1e305 03c3 8bda c1eb02 03c3 33d0 }
		$sequence_5 = { 8a12 80f257 8ada c0eb02 }
		$sequence_6 = { c1e305 03c3 8bda c1eb02 03c3 33d0 }
		$sequence_7 = { 53 80ef18 80ff10 5b }
		$sequence_8 = { 80f457 8acc 80e103 8aec }
		$sequence_9 = { ac 8bda c1e305 03c3 8bda }

	condition:
		7 of them and filesize <1106944
}
