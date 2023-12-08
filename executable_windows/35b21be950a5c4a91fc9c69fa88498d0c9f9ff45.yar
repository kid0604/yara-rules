rule win_manjusaka_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.manjusaka."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.manjusaka"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 7e14 488b8e88000000 488d1440 6683e32e 66895cd1ea 8bc5 488b5c2450 }
		$sequence_1 = { c3 488d05b4121b00 4889442420 488d0d70121b00 4c8d0db9051900 4c8d442430 ba37000000 }
		$sequence_2 = { 49894608 e9???????? 31c9 4885c9 488d2d3cf21300 480f45e9 480f44f1 }
		$sequence_3 = { ffc3 498d4e50 e8???????? 4839d0 7426 4889c1 4989d7 }
		$sequence_4 = { 7559 488b5710 4885d2 7450 e8???????? 85c0 7547 }
		$sequence_5 = { ffc8 8b542470 488bcd 89442444 e8???????? 418b442438 448bc6 }
		$sequence_6 = { c1e012 c1e706 4183e63f 4109fe 4109c6 4181fe00001100 408a6c2433 }
		$sequence_7 = { e8???????? 450fbf4e46 41bd02000000 8b45c4 4503cd 488bce 89442420 }
		$sequence_8 = { 498d142f 410fb6c1 4c8d052ae80900 41c1e908 b90d000000 89442420 e8???????? }
		$sequence_9 = { e9???????? 488d0d2aaf0f00 4c8d054baf0f00 ba21000000 e8???????? e9???????? c685d705000001 }

	condition:
		7 of them and filesize <4772864
}
