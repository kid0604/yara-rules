rule elf_persirai_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects elf.persirai."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/elf.persirai"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "linux"
		filetype = "executable"

	strings:
		$sequence_0 = { eb0f 31db eb2f 0dffff1f00 8db021feffff 8d6c240c 8b5e3c }
		$sequence_1 = { 7524 eb0a 8b401c 89da e8???????? 89b3bc010000 85f6 }
		$sequence_2 = { 6a02 e8???????? 83c410 83c40c c3 83ec0c 8b442414 }
		$sequence_3 = { e8???????? 83c40c 57 8d44243c 50 56 e8???????? }
		$sequence_4 = { 5f 5d c3 a1???????? 53 89c3 8b15???????? }
		$sequence_5 = { 50 6a02 e8???????? a1???????? 5f ff7018 e8???????? }
		$sequence_6 = { 83ec10 8b5c2418 ff74241c 53 e8???????? 83c410 83caff }
		$sequence_7 = { 7413 8d4310 89742410 89442414 59 5b 5e }
		$sequence_8 = { 85c0 7436 8d4304 51 51 50 }
		$sequence_9 = { 50 e8???????? 895e08 eb0d 8d4610 51 51 }

	condition:
		7 of them and filesize <229376
}
