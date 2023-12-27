rule win_turnedup_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.turnedup."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.turnedup"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4dfc 5f 5e 33cd 895004 5b }
		$sequence_1 = { 7706 891d???????? ff0d???????? 7506 891d???????? 6a01 }
		$sequence_2 = { 8b07 8b4004 03c7 33d2 8955dc c645e001 8b4838 }
		$sequence_3 = { 895dfc 752b 6a00 8d4df8 e8???????? 833d????????00 }
		$sequence_4 = { 68???????? 8819 e8???????? 8d7dac }
		$sequence_5 = { c746180f000000 894614 56 884604 e8???????? 83c404 }
		$sequence_6 = { 830801 8b4dd8 394dc0 741e 837dd000 }
		$sequence_7 = { 8945bc 8975b0 8b55f4 8b45e0 83fa10 7303 8d45e0 }
		$sequence_8 = { 8ad5 c0ea04 80e203 02d0 8a45f6 8855f8 8ad0 }
		$sequence_9 = { 8b45bc 8a11 8810 8b0b 40 }

	condition:
		7 of them and filesize <892928
}