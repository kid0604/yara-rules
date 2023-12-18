rule win_grease_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.grease."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.grease"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 52 50 683f000f00 50 50 50 }
		$sequence_1 = { 488b4c2460 ff15???????? b801000000 488b8c2480020000 4833cc e8???????? 4881c490020000 }
		$sequence_2 = { 4533c0 488bd3 c744242804000000 4889442420 ff15???????? 488b4c2450 ff15???????? }
		$sequence_3 = { 488b05???????? 4833c4 4889842480020000 488d4c2472 }
		$sequence_4 = { c74424281f000200 895c2420 ff15???????? 85c0 0f85e7000000 }
		$sequence_5 = { 4533c9 48897c2440 4889442438 48897c2430 }
		$sequence_6 = { 48895c2440 48895c2458 895c2460 48895c2468 }
		$sequence_7 = { 4889442438 48897c2430 4533c0 c74424283f000f00 897c2420 ff15???????? 85c0 }
		$sequence_8 = { 488b4c2450 488d442458 41b904000000 4533c0 488bd3 }
		$sequence_9 = { 55 68000000c0 50 ff15???????? 8bf0 }
		$sequence_10 = { e9???????? c684342c08000023 e9???????? c684342c08000021 e9???????? c684342c08000025 }
		$sequence_11 = { 51 683f000f00 6a00 8d542424 52 6802000080 ffd7 }
		$sequence_12 = { 85c0 7540 8d542420 52 8b542414 }
		$sequence_13 = { 83c001 3acb 75f7 8b2d???????? }
		$sequence_14 = { 83c404 85f6 8854240c 8d46ff 7412 8a4c040c }
		$sequence_15 = { e9???????? c684341001000066 e9???????? c684341001000068 e9???????? }
		$sequence_16 = { e8???????? 8b0d???????? 51 8d542418 }
		$sequence_17 = { e9???????? c6440c082b e9???????? c6440c083e e9???????? c6440c083d e9???????? }
		$sequence_18 = { c68434240600003f eb12 c68434240600002e eb08 }
		$sequence_19 = { 8a08 40 84c9 7405 46 85c0 }
		$sequence_20 = { 8b9c2418040000 56 57 b90d000000 be???????? }
		$sequence_21 = { 50 897c2430 ffd5 8b542410 6a04 8d4c241c 51 }
		$sequence_22 = { 8d942434010000 52 56 ffd7 b83b000000 53 668984242c010000 }

	condition:
		7 of them and filesize <278528
}
