rule Linux_Trojan_BPFDoor_e14b0b79
{
	meta:
		author = "Elastic Security"
		id = "e14b0b79-a6f3-4fb3-a314-0ec20dcd242c"
		fingerprint = "1c4cb6c8a255840c5a2cb7674283678686e228dc2f2a9304fa118bb5bdc73968"
		creation_date = "2022-05-10"
		last_modified = "2022-05-10"
		threat_name = "Linux.Trojan.BPFDoor"
		reference_sample = "dc8346bf443b7b453f062740d8ae8d8d7ce879672810f4296158f90359dcae3a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan BPFDoor"
		filetype = "executable"

	strings:
		$a1 = "getpassw" ascii fullword
		$a2 = "(udp[8:2]=0x7255) or (icmp[8:2]=0x7255) or (tcp[((tcp[12]&0xf0)>>2):2]=0x5293)" ascii fullword
		$a3 = "/var/run/haldrund.pid" ascii fullword
		$a4 = "Couldn't install filter %s: %s" ascii fullword
		$a5 = "godpid" ascii fullword

	condition:
		all of them
}
