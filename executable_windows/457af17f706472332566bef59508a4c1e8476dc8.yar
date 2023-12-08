rule win_zerocleare_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.zerocleare."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.zerocleare"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8b4c2428 8b54242c 890424 8b442430 6a00 }
		$sequence_1 = { c705????????80700000 33c0 c705????????01000000 c705????????f0f1ffff c705????????a0d94400 c3 8bff }
		$sequence_2 = { a3???????? a3???????? 8d4de8 e8???????? 8b3d???????? 3b7b0c 730c }
		$sequence_3 = { 740a 6bfa38 033c8d40fd4400 f6472d01 }
		$sequence_4 = { 8d04fd00000000 894dfc 8b7df4 8d1401 8945e8 }
		$sequence_5 = { 8b45f8 eb0a 8d040a 3b45f8 0f4245f8 8d0cc500000000 894dec }
		$sequence_6 = { 6a00 1bc0 6a18 8954241c }
		$sequence_7 = { 56 8bcf c705????????bca04300 e8???????? 68???????? }
		$sequence_8 = { 833d????????00 0f852ce4ffff 8d0dc0524400 ba1b000000 e9???????? a900000080 }
		$sequence_9 = { 8b06 8d4908 8941f8 8b4604 8941fc c70600000000 c7460400000000 }

	condition:
		7 of them and filesize <42670080
}
