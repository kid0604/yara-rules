rule win_nemim_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nemim."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nemim"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 8a0e 83c40c 8808 8b16 c1ea08 885001 8b0e }
		$sequence_1 = { 8b5308 8b7304 8b03 8bcf 33ca 23ce 33cf }
		$sequence_2 = { 5e 5b c9 c20400 8bc1 c700???????? c3 }
		$sequence_3 = { 8945d0 0f879a060000 ff24856a064100 834df0ff 8955cc 8955d8 }
		$sequence_4 = { 8bec 8b550c 8b4d08 53 56 85d2 b8???????? }
		$sequence_5 = { 51 e8???????? 8dbc24600a0000 83c9ff 33c0 }
		$sequence_6 = { 8b560c c1ea18 88500f c70600000000 5f }
		$sequence_7 = { 50 50 56 ff15???????? eb55 8b9424bc000000 6a00 }
		$sequence_8 = { 8bcf 8b6c2430 c1e70e c1e912 0bcf 8bfe 03ce }
		$sequence_9 = { c7461c60764100 c7462060754100 c7462440794100 c7462860724100 }

	condition:
		7 of them and filesize <499712
}