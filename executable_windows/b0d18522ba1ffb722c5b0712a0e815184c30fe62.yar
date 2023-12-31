rule win_cameleon_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.cameleon."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.cameleon"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d4d8c e9???????? 8d8d68ffffff e9???????? 8d4d8c }
		$sequence_1 = { c645fc16 8b854cffffff 83f808 7213 40 }
		$sequence_2 = { 3914c5f81d0510 7408 40 83f81d 7cf1 eb07 8b0cc5fc1d0510 }
		$sequence_3 = { 56 8b048550d60510 33db 8b7508 57 8b440818 8b4d10 }
		$sequence_4 = { 8b049550d60510 f644082880 7507 33c0 e9???????? 56 8b7524 }
		$sequence_5 = { 83ec70 53 56 57 8bda 894df0 c745ec00000000 }
		$sequence_6 = { 8b10 8bc8 6a01 ff12 33c0 c78518ffffff07000000 }
		$sequence_7 = { 8b3f 83ec18 8bd4 8965cc c7421000000000 c7421400000000 c7421407000000 }
		$sequence_8 = { 83fb23 7605 e8???????? 8bd8 53 e8???????? 8b4df4 }
		$sequence_9 = { 64890d00000000 8be5 5d c21000 8b06 8b4804 }

	condition:
		7 of them and filesize <824320
}
