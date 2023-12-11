rule EQGRP_EPBA
{
	meta:
		description = "EQGRP Toolset Firewall - file EPBA.script"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		hash1 = "53e1af1b410ace0934c152b5df717d8a5a8f5fdd8b9eb329a44d94c39b066ff7"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "./epicbanana_2.0.0.1.py -t 127.0.0.1 --proto=ssh --username=cisco --password=cisco --target_vers=asa804 --mem=NA -p 22 " fullword ascii
		$x2 = "-t TARGET_IP, --target_ip=TARGET_IP -- Either 127.0.0.1 or Win Ops IP" fullword ascii
		$x3 = "./bride-1100 --lp 127.0.0.1 --implant 127.0.0.1 --sport RHP --dport RHP" fullword ascii
		$x4 = "--target_vers=TARGET_VERS    target Pix version (pix712, asa804) (REQUIRED)" fullword ascii
		$x5 = "-p DEST_PORT, --dest_port=DEST_PORT defaults: telnet=23, ssh=22 (optional) - Change to LOCAL redirect port" fullword ascii
		$x6 = "this operation is complete, BananaGlee will" fullword ascii
		$x7 = "cd /current/bin/FW/BGXXXX/Install/LP" fullword ascii

	condition:
		( uint16(0)==0x2023 and filesize <7KB and 1 of ($x*)) or (3 of them )
}
