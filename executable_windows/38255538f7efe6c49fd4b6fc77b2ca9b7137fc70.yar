rule win_cabart_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.cabart."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cabart"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8930 8b4510 eb16 395d10 740f }
		$sequence_1 = { 8d8500fcffff 50 ff35???????? be00020000 ff35???????? }
		$sequence_2 = { 3bc3 7620 8d4df0 51 50 }
		$sequence_3 = { 33c0 66898506fcffff 8d8500fcffff 50 ff35???????? be00020000 }
		$sequence_4 = { 8d0c30 3bcf 7732 3bc3 }
		$sequence_5 = { 8d85fcfeffff 68???????? 6804010000 50 ff15???????? 83c410 6a10 }
		$sequence_6 = { 85db 750a 68b90b0000 e8???????? 85ed }
		$sequence_7 = { 3bc7 750a 68ec030000 e9???????? 8bc8 }
		$sequence_8 = { 57 8d45e8 50 6a58 56 }
		$sequence_9 = { ff15???????? 57 8d45f4 50 6a3f 56 c745f40a000000 }

	condition:
		7 of them and filesize <32768
}
