rule win_snojan_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.snojan."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.snojan"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { ff15???????? 83ec0c 83f8ff 0f8487010000 89c7 b802000000 c70424???????? }
		$sequence_1 = { b802000000 c70424???????? 6689442420 ff15???????? 83ec04 c70424???????? 89442424 }
		$sequence_2 = { 8d5c2430 c644241f00 c744240c00000000 c744240800900100 895c2404 893c24 ff15???????? }
		$sequence_3 = { a1???????? 8b988000986d 85db 74da }
		$sequence_4 = { 8d860000986d 8955cc e8???????? 8b45cc }
		$sequence_5 = { 893c24 ff15???????? 83ec10 83f800 }
		$sequence_6 = { e9???????? 0fb7810000986d 894dc0 89c7 81cf0000ffff 6683b90000986d00 0f48c7 }
		$sequence_7 = { 85c0 74e9 a1???????? 8b988000986d 85db 74da 895c2404 }
		$sequence_8 = { 837c243401 753d c744241400000000 c744241000000000 }
		$sequence_9 = { 85c0 b801000000 0f44d0 8854241f 8974240c 896c2408 }

	condition:
		7 of them and filesize <90112
}
