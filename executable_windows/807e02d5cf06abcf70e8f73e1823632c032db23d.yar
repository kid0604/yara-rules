rule UnPack_rar_Folder_TBack
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file TBack.DLL"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "30fc9b00c093cec54fcbd753f96d0ca9e1b2660f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Redirect SPort RemoteHost RPort       -->Port Redirector" fullword ascii
		$s1 = "http://IP/a.exe a.exe                 -->Download A File" fullword ascii
		$s2 = "StopSniffer                           -->Stop Pass Sniffer" fullword ascii
		$s3 = "TerminalPort Port                     -->Set New Terminal Port" fullword ascii
		$s4 = "Example: Http://12.12.12.12/a.exe abc.exe" fullword ascii
		$s6 = "Create Password Sniffering Thread Successfully. Status:Logging" fullword ascii
		$s7 = "StartSniffer NIC                      -->Start Sniffer" fullword ascii
		$s8 = "Shell                                 -->Get A Shell" fullword ascii
		$s11 = "DeleteService ServiceName             -->Delete A Service" fullword ascii
		$s12 = "Disconnect ThreadNumber|All           -->Disconnect Others" fullword ascii
		$s13 = "Online                                -->List All Connected IP" fullword ascii
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword ascii
		$s16 = "Example: Set REG_SZ Test Trojan.exe" fullword ascii
		$s18 = "Execute Program                       -->Execute A Program" fullword ascii
		$s19 = "Reboot                                -->Reboot The System" fullword ascii
		$s20 = "Password Sniffering Is Not Running" fullword ascii

	condition:
		4 of them
}
