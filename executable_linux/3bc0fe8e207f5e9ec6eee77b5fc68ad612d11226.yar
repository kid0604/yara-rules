rule Linux_Trojan_Dropperl_c4018572
{
	meta:
		author = "Elastic Security"
		id = "c4018572-a8af-4204-bc19-284a2a27dfdd"
		fingerprint = "f2ede50ea639af593211c9ef03ee2847a32cf3eb155db4e2ca302f3508bf2a45"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dropperl"
		reference_sample = "c1515b3a7a91650948af7577b613ee019166f116729b7ff6309b218047141f6d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dropperl"
		filetype = "executable"

	strings:
		$a = { E8 97 FB FF FF 83 7D D4 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}
