rule win_netspy_auto_alt_2
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.netspy."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.netspy"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { e9???????? 488b8540010000 488b8db8190000 4889c4 488b8558180000 488985d0000000 }
		$sequence_1 = { e9???????? 488b8548340000 8b8d944d0000 4889c4 488b85484d0000 }
		$sequence_2 = { 488b09 4863493c 4801c8 48898528340000 8b15???????? }
		$sequence_3 = { 3d3f08c577 0f84d6280000 e9???????? 8b8584130000 }
		$sequence_4 = { 48898d904d0000 e8???????? 4829c4 488b85500a0000 4889e1 48898d984d0000 }
		$sequence_5 = { 0f8488000000 e9???????? 8b8554340000 3ddf29d6fa 0f84d0010000 }
		$sequence_6 = { e8???????? 4829c4 488b8540180000 4889e2 48899550180000 }
		$sequence_7 = { c70163382994 e8???????? 4829c4 4889e0 488985e05e0000 e9???????? }

	condition:
		7 of them and filesize <12033024
}
