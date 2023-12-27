rule win_sepulcher_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.sepulcher."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sepulcher"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 56 57 6a43 8bf9 58 6a4d 8db784480000 }
		$sequence_1 = { 7515 6a04 8d45bc 50 e8???????? 8b4db8 8bd0 }
		$sequence_2 = { 58 6a74 59 6a53 668945ea 58 }
		$sequence_3 = { 0fb71408 8bc2 c1e002 66393408 75f1 }
		$sequence_4 = { eb1a 8d45fc 50 8b04bd50de0110 ff743018 }
		$sequence_5 = { 668945d2 b8???????? 66894db4 66894dba 66894dc0 }
		$sequence_6 = { 56 57 6a5a 58 6a52 }
		$sequence_7 = { c1f906 6bd030 8b45fc 03148d50de0110 8b00 894218 }
		$sequence_8 = { 8bd8 895db0 8d0c4dffff0000 51 57 53 e8???????? }
		$sequence_9 = { 58 6a33 668945e8 668945ea 58 6a32 668945ec }

	condition:
		7 of them and filesize <279552
}