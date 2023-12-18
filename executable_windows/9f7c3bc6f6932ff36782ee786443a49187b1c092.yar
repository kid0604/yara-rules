rule win_royalcli_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.royalcli."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.royalcli"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 41 3bcf 7cb5 56 }
		$sequence_1 = { e8???????? 33f6 83c42c 3bc6 0f8c19050000 83bda4feffff1c 0f8c0c050000 }
		$sequence_2 = { 5d c3 56 ff15???????? 5b 5f 33c0 }
		$sequence_3 = { 898dccf9ffff 7d10 33c0 8b4dfc }
		$sequence_4 = { 8b08 8d954cf7ffff 52 68???????? }
		$sequence_5 = { 33f6 ff15???????? e9???????? 8b4708 }
		$sequence_6 = { 6a01 50 e8???????? 56 8945dc e8???????? 8b55e0 }
		$sequence_7 = { 83c414 8955e4 2bd0 8d9b00000000 }
		$sequence_8 = { 8bbdd4f9ffff 8b9dc4f9ffff 807c3b0f00 751c 8b4b08 8b5508 }
		$sequence_9 = { 50 e8???????? 6820010000 8d8dc0fdffff 56 51 e8???????? }

	condition:
		7 of them and filesize <204800
}
