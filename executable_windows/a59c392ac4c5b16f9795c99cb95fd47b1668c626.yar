rule win_poortry_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2023-07-11"
		version = "1"
		description = "Detects win.poortry."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.poortry"
		malpedia_rule_date = "20230705"
		malpedia_hash = "42d0574f4405bd7d2b154d321d345acb18834a41"
		malpedia_version = "20230715"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { 41f7d2 f9 4181f80255e860 4181f225619d1f 41f7da f8 4181c2174c0279 }
		$sequence_1 = { 66f7c4e120 310424 5e 41f6c105 443af4 4863c0 f5 }
		$sequence_2 = { 66443bf0 56 0fbae697 c1e61f 311424 f9 660fbafec8 }
		$sequence_3 = { 41f7d3 4151 450aca 6641d3e1 44311c24 4180d1a2 }
		$sequence_4 = { f8 81f79e0d521c f8 d1cf 81c71d19891d f8 f5 }
		$sequence_5 = { 4151 41c0e937 4d0fb7c9 313424 450fc0c9 66450fabf1 66410fbae1d7 }
		$sequence_6 = { 4484c7 81c33f50eb3f 664181f8ec0e f7db 4153 311c24 6641c1c318 }
		$sequence_7 = { 56 401af3 40d2e6 66f7c4e120 310424 5e 41f6c105 }
		$sequence_8 = { 4123ea 48c1d5cd 5d f9 4d63c9 4881f98925786f 664185d3 }
		$sequence_9 = { f6dd 4159 4084ee 40b5c4 9d 66400fbecd 59 }

	condition:
		7 of them and filesize <8078336
}
