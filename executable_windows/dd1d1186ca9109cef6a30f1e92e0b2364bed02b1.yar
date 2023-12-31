rule win_wastedloader_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.wastedloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.wastedloader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { b748 00ee 0be6 3bf6 2014dd33b89819 220f }
		$sequence_1 = { 0fb7485e 83e954 8b55f8 66894a5e }
		$sequence_2 = { fc b802ec0000 8d6825 94 01dc 00e8 45 }
		$sequence_3 = { b802ec0000 8d6825 94 01dc 00e8 45 }
		$sequence_4 = { ec 7ac4 f8 ae fc }
		$sequence_5 = { 32705b 39e1 108792ff9b95 8abf2ec8650b }
		$sequence_6 = { 1a00 0071bf 7303 1f c8be8de8 1be8 692405008008202c00700d }
		$sequence_7 = { 66894118 8b55f8 0fb74218 83e854 8b4df8 66894118 ba8d000000 }
		$sequence_8 = { 2cbe 832061 5b 5b }
		$sequence_9 = { 30ac06e68bfc49 23f7 b754 7c49 27 59 }

	condition:
		7 of them and filesize <2677760
}
