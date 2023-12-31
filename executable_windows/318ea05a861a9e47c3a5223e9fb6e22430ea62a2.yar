rule win_firechili_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.firechili."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.firechili"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 85c9 7876 4881fbfeffff7f 7610 b80d0000c0 488b5c2408 }
		$sequence_1 = { ff15???????? ff15???????? 4885ff 7428 4c3bf3 7442 85ed }
		$sequence_2 = { c684249800000000 4c8bf3 498bdc 85ed 7435 488b842488000000 }
		$sequence_3 = { 400fb6ff 488d4c2420 84c0 410f45ff ff15???????? 4084ff 750e }
		$sequence_4 = { 48895c2430 488b9ab8000000 4885db 0f8496000000 817b181b001200 }
		$sequence_5 = { 0f11459f ff15???????? 488d4d17 ff15???????? 4885c0 7413 488d5567 }
		$sequence_6 = { 7c22 4c8b0d???????? 4d85c9 740d 4c8d442430 488bcb 41ffd1 }
		$sequence_7 = { 8b03 4889442440 4885f6 780a 488d4c2420 e8???????? }
		$sequence_8 = { 664585db 750c 410fb7d0 488bcb 48d1ea eb05 b80d0000c0 }
		$sequence_9 = { 4c89742438 4533f6 90 483bde 742d 488b07 }

	condition:
		7 of them and filesize <91136
}
