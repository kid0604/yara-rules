rule win_vhd_ransomware_auto_alt_3
{
	meta:
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		date = "2024-10-31"
		version = "1"
		description = "Detects win.vhd_ransomware."
		info = "autogenerated rule brought to you by yara-signator"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.vhd_ransomware"
		malpedia_rule_date = "20241030"
		malpedia_hash = "26e26953c49c8efafbf72a38076855d578e0a2e4"
		malpedia_version = "20241030"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"
		os = "windows"
		filetype = "executable"

	strings:
		$sequence_0 = { a1???????? 33c5 8945fc 53 8bd9 8b13 57 }
		$sequence_1 = { 83c410 8dbdf0fdffff e8???????? a1???????? e9???????? }
		$sequence_2 = { 33d2 e8???????? 8b4d08 0bc7 }
		$sequence_3 = { 8b450c 8902 33c0 89a578f6ffff 39450c 7e11 8d4a04 }
		$sequence_4 = { 83c404 a1???????? 8b3d???????? 40 6a00 c1e018 }
		$sequence_5 = { 8b4d08 85c9 7538 33c0 b9c8000000 }
		$sequence_6 = { 333c9598754100 337e04 ff4de8 897804 8b38 }
		$sequence_7 = { f7e2 0f90c1 89b518f0ffff f7d9 0bc8 51 }
		$sequence_8 = { 8945cc bf40000000 b8???????? 8d75e0 895dc8 c745f40f000000 c745f000000000 }
		$sequence_9 = { d9bd1ee6ffff 0fb7851ee6ffff 0d000c0000 898518e6ffff 43 d9ad18e6ffff db9d18e6ffff }

	condition:
		7 of them and filesize <275456
}
