rule Explosion_Sample_1
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://goo.gl/5vYaNb"
		date = "2015/04/03"
		score = 70
		hash = "c97693ecb36247bdb44ab3f12dfeae8be4d299bb"
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "REG ADD \"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii
		$s9 = "WinAutologon From Winlogon Reg" fullword ascii
		$s10 = "82BD0E67-9FEA-4748-8672-D5EFE5B779B0" fullword ascii
		$s11 = "IE:Password-Protected sites" fullword ascii
		$s12 = "\\his.sys" ascii
		$s13 = "HTTP Password" fullword ascii
		$s14 = "\\data.sys" ascii
		$s15 = "EL$_RasDefaultCredentials#0" fullword wide
		$s17 = "Office Outlook HTTP" fullword ascii
		$s20 = "Hist :<b> %ws</b>  :%s </br></br>" fullword ascii

	condition:
		all of them and uint16(0)==0x5A4D
}
