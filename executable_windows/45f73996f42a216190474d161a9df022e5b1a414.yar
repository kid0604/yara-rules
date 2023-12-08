rule TeleBots_CredRaptor_Password_Stealer
{
	meta:
		description = "Detects TeleBots malware - CredRaptor Password Stealer"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4if3HG"
		date = "2016-12-14"
		modified = "2023-01-06"
		hash1 = "50b990f6555055a265fde98324759dbc74619d6a7c49b9fd786775299bf77d26"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\Documents and Settings\\Administrator\\Desktop\\GetPAI\\Out\\IE.pdb" fullword ascii
		$s2 = "SELECT encryptedUsername, encryptedPassword, hostname,httpRealm FROM moz_logins" fullword ascii
		$s3 = "SELECT ORIGIN_URL,USERNAME_VALUE,PASSWORD_VALUE FROM LOGINS" fullword ascii
		$s4 = ".\\PAI\\IEforXPpasswords.txt" ascii
		$s5 = "\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii
		$s6 = "Opera old version credentials" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 2 of them ) or (4 of them )
}
