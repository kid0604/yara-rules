rule win_hellokitty_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.hellokitty."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hellokitty"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8975fc 8d4e08 c706???????? e8???????? 6818010000 8d86d0030000 6a00 }
		$sequence_1 = { 23df 234df0 8bc7 c1c802 0bd9 33d0 03de }
		$sequence_2 = { 7509 0fb64702 3a4604 7411 83c32c 41 83c72c }
		$sequence_3 = { 33d2 8b45ec 8bf1 0fa4c11e c1ee02 0bd1 c1e01e }
		$sequence_4 = { 8b048520364200 56 8b7508 57 8b4c0818 8b4514 832600 }
		$sequence_5 = { 33ca 8bd1 894dec 8988a8000000 33d3 }
		$sequence_6 = { 8b759c 03c2 8bd1 8945f8 8bc1 c1c807 c1c20e }
		$sequence_7 = { 8b45c0 3175c4 8bf0 0facc81c c1e604 0bd0 c1e91c }
		$sequence_8 = { 8bf8 83c020 59 f3a5 8b7508 83ee20 89450c }
		$sequence_9 = { c1ce02 8b45d0 03cf 3345ec 3345c4 3345f0 8b7df4 }

	condition:
		7 of them and filesize <319488
}
