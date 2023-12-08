import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_References_Messaging_Clients
{
	meta:
		description = "Detects executables referencing many email and collaboration clients. Observed in information stealers"
		author = "ditekSHen"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook" fullword ascii wide
		$s2 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" fullword ascii wide
		$s3 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles" fullword ascii wide
		$s4 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" ascii wide
		$s5 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail" ascii wide
		$s6 = "VirtualStore\\Program Files\\Foxmail\\mail" ascii wide
		$s7 = "VirtualStore\\Program Files (x86)\\Foxmail\\mail" ascii wide
		$s8 = "Opera Mail\\Opera Mail\\wand.dat" ascii wide
		$s9 = "Software\\IncrediMail\\Identities" ascii wide
		$s10 = "Pocomail\\accounts.ini" ascii wide
		$s11 = "Software\\Qualcomm\\Eudora\\CommandLine" ascii wide
		$s12 = "Mozilla Thunderbird\\nss3.dll" ascii wide
		$s13 = "SeaMonkey\\nss3.dll" ascii wide
		$s14 = "Flock\\nss3.dll" ascii wide
		$s15 = "Postbox\\nss3.dll" ascii wide
		$s16 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook" ascii wide
		$s17 = "CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook" ascii wide
		$s18 = "Software\\Microsoft\\Office\\Outlook\\OMI Account Manager\\Accounts" ascii wide
		$s19 = "Software\\Microsoft\\Internet Account Manager\\Accounts" ascii wide
		$s20 = "Files\\Telegram" ascii wide
		$s21 = "Telegram Desktop\\tdata" ascii wide
		$s22 = "Files\\Discord" ascii wide
		$s23 = "Steam\\config" ascii wide
		$s24 = ".purple\\accounts.xml" ascii wide
		$s25 = "Skype\\" ascii wide
		$s26 = "Pigdin\\accounts.xml" ascii wide
		$s27 = "Psi\\accounts.xml" ascii wide
		$s28 = "Psi+\\accounts.xml" ascii wide
		$s29 = "Psi\\profiles" ascii wide
		$s30 = "Psi+\\profiles" ascii wide
		$s31 = "Microsoft\\Windows Mail\\account{" ascii wide
		$s32 = "}.oeaccount" ascii wide
		$s33 = "Trillian\\users" ascii wide
		$s34 = "Google Talk\\Accounts" nocase ascii wide
		$s35 = "Microsoft\\Windows Live Mail" nocase ascii wide
		$s36 = "Google\\Google Talk" nocase ascii wide
		$s37 = "Yahoo\\Pager" nocase ascii wide
		$s38 = "BatMail\\" nocase ascii wide
		$s39 = "POP Peeper\\poppeeper.ini" nocase ascii wide
		$s40 = "Netease\\MailMaster\\data" nocase ascii wide
		$s41 = "Software\\Microsoft\\Office\\17.0\\Outlook\\Profiles\\Outlook" ascii wide
		$s42 = "Software\\Microsoft\\Office\\18.0\\Outlook\\Profiles\\Outlook" ascii wide
		$s43 = "Software\\Microsoft\\Office\\19.0\\Outlook\\Profiles\\Outlook" ascii wide
		$s45 = "Paltalk NG\\common_settings\\core\\users\\creds" ascii wide
		$s46 = "Discord\\Local Storage\\leveldb" ascii wide
		$s47 = "Discord PTB\\Local Storage\\leveldb" ascii wide
		$s48 = "Discord Canary\\leveldb" ascii wide
		$s49 = "MailSpring\\" ascii wide

	condition:
		uint16(0)==0x5a4d and 6 of them
}
