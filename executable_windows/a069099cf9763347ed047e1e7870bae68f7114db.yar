rule win_hodur_auto
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.hodur."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.hodur"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { c60647 89c1 80c107 308c04d6000000 40 75f1 8db424c4000000 }
		$sequence_1 = { 7c70 a1???????? 8d48ff 0fafc8 83e101 7460 ff75e4 }
		$sequence_2 = { ff75ec ffd0 8b4df0 e8???????? 89f9 e8???????? 31c0 }
		$sequence_3 = { c7460428381836 c746080c043500 7c12 a1???????? 8d48ff 0fafc8 83e101 }
		$sequence_4 = { ffb42474040000 ffd0 83f8ff 741f 833d????????0a 7c20 a1???????? }
		$sequence_5 = { ffd0 c7430271706600 66c703537f 89d9 660f6e4301 660f60c0 660f61c0 }
		$sequence_6 = { eb25 8d4a60 88e3 88cc 30dc 84c0 88a4148c000000 }
		$sequence_7 = { e8???????? 833d????????0a 7c1a 8b0d???????? 8d51ff 0fafd1 83e201 }
		$sequence_8 = { e9???????? 55 53 57 56 a1???????? 8b2d???????? }
		$sequence_9 = { 81ec30010000 b8f4ffffff c7442406b792a0b4 c744240ab4a1a6a4 c744240e8eb49a00 c7042400000000 c74424141c010000 }

	condition:
		7 of them and filesize <1067008
}
