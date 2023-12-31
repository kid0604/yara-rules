rule win_sfile_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sfile."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sfile"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 50 e8???????? 8b4d08 8b5144 }
		$sequence_1 = { 8b55fc 83c201 8955fc 837dfc08 7d12 }
		$sequence_2 = { e8???????? 83c41c eb2b 837d0803 7525 }
		$sequence_3 = { 8bec 83ec20 8b4508 8b888c050000 }
		$sequence_4 = { eb13 8b55f8 8b4210 8d0c8510000000 }
		$sequence_5 = { 51 ff15???????? 8b55f0 52 ff15???????? 8b45ec 50 }
		$sequence_6 = { c745fc08000000 eb09 8b85b8fdffff 8945fc 8b4dfc 83c106 }
		$sequence_7 = { 8d4c0002 8b55e8 894a04 8b45f8 }
		$sequence_8 = { 68fc000000 8b4df0 8b11 52 }
		$sequence_9 = { c60100 837dec00 7547 6af5 ff15???????? 8945f0 }

	condition:
		7 of them and filesize <588800
}
