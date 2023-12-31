rule win_putabmow_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.putabmow."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.putabmow"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 5b 8be5 5d c20400 8b4f08 2bce b8398ee338 }
		$sequence_1 = { 8bce e8???????? 81c690000000 3bf7 75ef 5f 5e }
		$sequence_2 = { e8???????? 83c404 c78424900000000f000000 c784248c00000000000000 c644247c00 c684241801000003 837c247810 }
		$sequence_3 = { 83c404 837e1410 8bf8 7202 8b36 8d450c 8bce }
		$sequence_4 = { c784248800000001000000 8d442460 837c247408 b9???????? 6a01 0f43442464 6a01 }
		$sequence_5 = { 8d45cc 8bce 50 e8???????? c745fc00000000 c745c801000000 8bc6 }
		$sequence_6 = { eb02 03d9 3bda 8d4c242c 0f42da 53 e8???????? }
		$sequence_7 = { 895808 89480c 83fa01 7576 8b481c f7c1f8030000 746b }
		$sequence_8 = { 84c0 7479 83bc245802000010 8d8c2444020000 8b842454020000 0f438c2444020000 03c1 }
		$sequence_9 = { 8bcf 50 e8???????? 3d00dc0000 7207 3dffdf0000 761d }

	condition:
		7 of them and filesize <704512
}
