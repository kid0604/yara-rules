rule win_faketc_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.faketc."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.faketc"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e8???????? c684248001000002 8b442448 8b5004 8bce ffd2 84c0 }
		$sequence_1 = { e8???????? 83c410 6a5e 8d8576f7ffff 50 6a00 6a00 }
		$sequence_2 = { 899158010000 8b4508 8b484c 8b55f8 668b4104 66894248 8b4df8 }
		$sequence_3 = { e8???????? 83c410 6a00 8b4d8c 51 6a01 8b5508 }
		$sequence_4 = { ffd6 50 b86f000000 e8???????? 83c404 a3???????? eb06 }
		$sequence_5 = { e9???????? 8d45d8 50 e8???????? c3 8d8548ffffff 50 }
		$sequence_6 = { c1fa04 8bc2 c1e81f 03c2 895c2410 0f842b010000 895c241c }
		$sequence_7 = { e8???????? 8b85b0fdffff 8b0d???????? 8d95b8fdffff 52 68???????? 50 }
		$sequence_8 = { e8???????? b917000000 8bf0 bf???????? f3a5 66a5 c745fc02000000 }
		$sequence_9 = { c745fc???????? c745f805000000 eb0e c745fc???????? c745f806000000 8b4d08 8b91fc030000 }

	condition:
		7 of them and filesize <6864896
}
