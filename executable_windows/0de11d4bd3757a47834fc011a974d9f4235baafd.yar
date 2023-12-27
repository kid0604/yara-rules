rule win_ceeloader_auto_alt_1
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-12-06"
		version = "1"
		description = "Detects win.ceeloader."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ceeloader"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 3bce 33f6 23c7 0bda 8bde c3 0bd3 }
		$sequence_1 = { 448b15???????? 4489c6 4431de 4589c3 4101f3 44891d???????? 4589c3 }
		$sequence_2 = { 664589c2 664489942490030000 440fbe05???????? 4183f074 664589c2 664489942492030000 440fbe05???????? }
		$sequence_3 = { 0bda 8bde 0bd3 3bce 23f3 7a04 0bda }
		$sequence_4 = { 8b842420010000 3b84241c010000 0f8433000000 8b842420010000 898424dc000000 e8???????? 8b8c241c010000 }
		$sequence_5 = { 3bdd 23fd 0bda 8bde 0bd3 3bce 5a }
		$sequence_6 = { 741d 4885ff c6435401 488d0d53880800 480f45cf 48894b48 e8???????? }
		$sequence_7 = { 88542433 0fbe05???????? 83f064 88c2 88542434 0fbe05???????? 83f076 }
		$sequence_8 = { 4489a42464020000 4403bc2464020000 4489bc2460020000 448bbc2460020000 4589dc 4181e45d386101 4489a4245c020000 }
		$sequence_9 = { 41c1e204 4489942448050000 44038c2448050000 44898c2444050000 448b8c2444050000 4189d2 4181e235913d02 }

	condition:
		7 of them and filesize <2321408
}