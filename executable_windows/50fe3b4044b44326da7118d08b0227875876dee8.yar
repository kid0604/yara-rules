import "pe"

rule files_Rubeus
{
	meta:
		description = "8099 - file Rubeus.exe"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
		date = "2021-12-12"
		hash1 = "0e09068581f6ed53d15d34fff9940dfc7ad224e3ce38ac8d1ca1057aee3e3feb"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "        Rubeus.exe dump [/luid:LOGINID] [/user:USER] [/service:krbtgt] [/server:BLAH.DOMAIN.COM] [/nowrap]" fullword wide
		$x2 = "        Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH" wide
		$x3 = "[!] GetSystem() - OpenProcessToken failed!" fullword wide
		$x4 = "        Rubeus.exe createnetonly /program:\"C:\\Windows\\System32\\cmd.exe\" [/show]" fullword wide
		$x5 = "[!] GetSystem() - ImpersonateLoggedOnUser failed!" fullword wide
		$x6 = "[X] You need to have an elevated context to dump other users' Kerberos tickets :( " fullword wide
		$x7 = "[*] No target SPN specified, attempting to build 'cifs/dc.domain.com'" fullword wide
		$x8 = "    Dump all current ticket data (if elevated, dump for all users), optionally targeting a specific service/LUID:" fullword wide
		$s9 = "Z:\\Agressor\\github.com-GhostPack\\Rubeus-master\\Rubeus\\obj\\Debug\\Rubeus.pdb" fullword ascii
		$s10 = "    Triage all current tickets (if elevated, list for all users), optionally targeting a specific LUID, username, or service:" fullword wide
		$s11 = "[X] /ticket:X must either be a .kirbi file or a base64 encoded .kirbi" fullword wide
		$s12 = "Action: Dump Kerberos Ticket Data (All Users)" fullword wide
		$s13 = "[*] Initializing Kerberos GSS-API w/ fake delegation for target '{0}'" fullword wide
		$s14 = "[*] Listing statistics about target users, no ticket requests being performed." fullword wide
		$s15 = "[X] OpenProcessToken error: {0}" fullword wide
		$s16 = "[X] CreateProcessWithLogonW error: {0}" fullword wide
		$s17 = "[*] Target service  : {0:x}" fullword wide
		$s18 = "[*] Target Users           : {0}" fullword wide
		$s19 = "        Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> [/domain:DOMAIN] </impersonateuser:USER | /tgs:BASE64 | /tgs:FILE.K" wide
		$s20 = "    List all current tickets in detail (if elevated, list for all users), optionally targeting a specific LUID:" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 1 of ($x*) and 4 of them
}
