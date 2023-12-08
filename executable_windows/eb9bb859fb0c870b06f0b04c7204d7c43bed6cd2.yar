rule win_bouncer_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.bouncer."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.bouncer"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 0f851df1ffff 6a1c 8d45dc 53 50 e8???????? }
		$sequence_1 = { 7413 807d1055 7411 6a05 56 ff15???????? }
		$sequence_2 = { 83c104 3bc6 72f4 3bc6 7512 83fe40 730d }
		$sequence_3 = { 8bd8 66c745e00200 ff15???????? 8b35???????? }
		$sequence_4 = { 8d848db8feffff 8b5004 41 8910 8b95b4feffff 83c004 4a }
		$sequence_5 = { 7509 c6843d34ffffff0a 47 6a06 8d8534ffffff }
		$sequence_6 = { ff75e4 ff15???????? 895de4 e9???????? 80f916 0f855f020000 8b45f0 }
		$sequence_7 = { 83c40c e9???????? 68???????? bf???????? 68???????? 57 }
		$sequence_8 = { 8975c4 899db4feffff e8???????? 83c40c 83f8ff }
		$sequence_9 = { 83ec14 53 56 57 6a01 5e 33db }

	condition:
		7 of them and filesize <335872
}
