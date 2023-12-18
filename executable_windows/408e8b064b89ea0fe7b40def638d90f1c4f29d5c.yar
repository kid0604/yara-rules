rule win_zeroaccess_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.zeroaccess."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zeroaccess"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 85c0 7408 ff15???????? eb02 }
		$sequence_1 = { 56 56 6a20 6a05 }
		$sequence_2 = { bf03000040 eb05 bf010000c0 85ff }
		$sequence_3 = { 6a01 8d45f4 50 ff7308 ff15???????? 85c0 }
		$sequence_4 = { 6a04 68???????? 6a10 68???????? 68060000c8 ff7708 ff15???????? }
		$sequence_5 = { ff15???????? 85c0 7407 b8e3030000 }
		$sequence_6 = { 56 6a10 8945e8 8d45e4 }
		$sequence_7 = { e8???????? 50 6819000200 8d45f8 }
		$sequence_8 = { 3bc1 7604 83c8ff c3 }
		$sequence_9 = { 50 68???????? 6889001200 8d45fc }
		$sequence_10 = { 56 8d45f8 50 ff15???????? 6a01 8d45f8 50 }
		$sequence_11 = { 33c0 48 83c9ff c744242804000000 48 }
		$sequence_12 = { 85db 741f 8b4304 49 }
		$sequence_13 = { 7615 83780815 750f c705????????01000000 }
		$sequence_14 = { 48 83ec20 41 8bf9 48 8bd9 }

	condition:
		7 of them and filesize <172032
}
