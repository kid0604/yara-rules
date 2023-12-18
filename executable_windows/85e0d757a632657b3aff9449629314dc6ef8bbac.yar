rule win_rtm_locker_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.rtm_locker."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.rtm_locker"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8d8d2cfeffff e8???????? 0f108d64fcffff 33c9 0f109574fcffff 0f109d84fcffff 0f10a594fcffff }
		$sequence_1 = { 0f104630 660fefd0 0f1006 660fefc8 0f110f 0f116710 0f115f20 }
		$sequence_2 = { 0f29442470 0f28842470010000 0f29842420010000 0f28842480010000 89442458 83c004 894c245c }
		$sequence_3 = { e8???????? 8d8d68ffffff e8???????? 0f108568ffffff be18000000 0f1185c8feffff }
		$sequence_4 = { 0fbe8098074200 40 8945cc 2b45dc 8945d4 3bc2 0f8f10020000 }
		$sequence_5 = { 50 6af5 eb03 50 6af6 ff15???????? 8b04bd500f4200 }
		$sequence_6 = { c1f910 884e02 8b4de0 0ac1 884603 8bc1 c1f808 }
		$sequence_7 = { 897dfc 897db8 894508 85c0 0f8f3ffeffff }
		$sequence_8 = { 8d442430 50 ff15???????? 8bf0 83feff 7431 }
		$sequence_9 = { 8b0c85500f4200 8b45f8 807c012800 7d46 }

	condition:
		7 of them and filesize <598016
}
