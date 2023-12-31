rule win_nymaim_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.nymaim."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.nymaim"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 89d8 01c8 31d2 f7f7 }
		$sequence_1 = { 09c0 0f94c1 09c8 6bc064 }
		$sequence_2 = { 31d2 f7f7 92 31d2 }
		$sequence_3 = { 92 31d2 bf64000000 f7f7 }
		$sequence_4 = { 38f0 83d100 38d0 83d900 }
		$sequence_5 = { c1eb13 331d???????? 31c3 c1e808 }
		$sequence_6 = { 38d0 83d900 c1e105 01c8 }
		$sequence_7 = { 00d3 8a16 301e 46 }
		$sequence_8 = { 8b4e08 014e04 8b5e0c 015e08 }
		$sequence_9 = { 8b12 8b4d0c 8b5d18 8b1b 4f 31c0 fec2 }
		$sequence_10 = { c1e808 31c3 895e0c 89d8 }
		$sequence_11 = { f7e0 0fc8 01d0 894704 }
		$sequence_12 = { 8b06 c1e00b 3306 8b5604 0116 8b4e08 014e04 }
		$sequence_13 = { 394c1f3c 0f8598000000 394c1f44 0f858e000000 89541f3c 488d4348 813d????????50db9eda }
		$sequence_14 = { 53 56 57 83ec44 8b4508 8d0d2030d201 }
		$sequence_15 = { 31d2 890c24 c744240400000000 8945f4 8955f0 e8???????? 8d0d8630d201 }
		$sequence_16 = { 458b443430 4189c4 894b64 894548 e9???????? 4131c0 66813d????????a2fe }
		$sequence_17 = { 0f8425720100 4883600800 4531c9 488b4d9f 83caff 488364242000 c60001 }
		$sequence_18 = { 56 83ec28 8b450c 8b4d08 8d154e30d201 }
		$sequence_19 = { 890424 894c2404 e8???????? 8d0d3430d201 }
		$sequence_20 = { 5b 5d c3 8b45f0 8b0c850440d201 }
		$sequence_21 = { 83ec44 8b4508 8d0d2030d201 31d2 890c24 c744240400000000 }
		$sequence_22 = { 4409ca 31da 4489d1 4189d0 4431c9 4521d0 4409cb }
		$sequence_23 = { 31c9 8b55f4 8b75ec 89723c c7424003000000 }
		$sequence_24 = { 55 89e5 83ec10 8b4508 8d0d3430d201 }
		$sequence_25 = { 443928 0f8508270100 488b4710 c705????????28000000 488b4f08 8b10 488b09 }
		$sequence_26 = { 31c9 44893d???????? e8???????? 4885c0 0f858bdcfdff 44313d???????? 4c897c2428 }
		$sequence_27 = { 415e 415d 415c c705????????aab110e2 882d???????? 5f 5e }
		$sequence_28 = { 4189f6 4531fe 4189f4 4131fe b9db6383d0 4101c6 4101de }

	condition:
		7 of them and filesize <2375680
}
