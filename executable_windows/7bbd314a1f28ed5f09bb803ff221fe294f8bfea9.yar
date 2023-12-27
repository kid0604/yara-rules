rule win_kins_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.kins."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.kins"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 8d45dc 8d75cc e8???????? 83f8ff 741f 8bc6 }
		$sequence_1 = { 8bfe 337dfc 23f8 33fe 037df0 8d9417937198fd 8b7dfc }
		$sequence_2 = { e8???????? 83f8ff 743d 47 3bfa }
		$sequence_3 = { f7d3 0bde 33d8 035df4 8dbc3ba72394ab c1c70f 8bd8 }
		$sequence_4 = { c1e008 0bc2 0fb65116 0fb64917 c1e008 0bc2 }
		$sequence_5 = { 0fb6c0 83e07f 8bf2 746f 0fb61c39 c1e608 48 }
		$sequence_6 = { 40 85f6 75d8 8b7510 3b16 7719 }
		$sequence_7 = { 33de 23df 33da 035908 8d840378a46ad7 c1c007 03c7 }
		$sequence_8 = { 8d8578fcffff 50 8d857cfdffff 50 }
		$sequence_9 = { ff4118 8b4118 83f838 762b eb0b c644081c00 }

	condition:
		7 of them and filesize <548864
}