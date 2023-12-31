rule win_gameover_dga_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.gameover_dga."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.gameover_dga"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 884617 33c0 40 e9???????? 8a4601 33db 8b6c2434 }
		$sequence_1 = { 397e08 0f84f0000000 8be9 894c2414 8bd1 8b4604 8a0c03 }
		$sequence_2 = { 48 7544 397714 763f 8b4710 ff34b0 }
		$sequence_3 = { 833d????????00 7566 8d8de8fdffff e8???????? 51 be???????? 56 }
		$sequence_4 = { 5f 5b c20c00 8bcf e8???????? 8bf0 }
		$sequence_5 = { 56 ff15???????? 85c0 7443 56 be???????? 8d85f8fdffff }
		$sequence_6 = { 8b84245c010000 40 e9???????? 8b476c 33c9 2bc3 }
		$sequence_7 = { ff760c ff7608 6a10 e8???????? 84c0 0f847a010000 8364241c00 }
		$sequence_8 = { e8???????? a1???????? ff7064 ff15???????? 6a53 8d55b8 8bf0 }
		$sequence_9 = { 7510 8b4f10 e8???????? 85c0 75e5 32c0 }

	condition:
		7 of them and filesize <540672
}
