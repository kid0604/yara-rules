rule Linux_Trojan_Dropperl_733c0330
{
	meta:
		author = "Elastic Security"
		id = "733c0330-3163-48f3-a780-49be80a3387f"
		fingerprint = "ee233c875dd3879b4973953a1f2074cd77abf86382019eeb72da069e1fd03e1c"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dropperl"
		reference_sample = "b303f241a2687dba8d7b4987b7a46b5569bd2272e2da3e0c5e597b342d4561b6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Dropperl"
		filetype = "executable"

	strings:
		$a = { E8 A0 FB FF FF 83 7D DC 00 79 0A B8 ?? ?? 60 00 }

	condition:
		all of them
}
