rule sekurlsa
{
	meta:
		description = "Chinese Hacktool Set - file sekurlsa.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "6acecd18fc7da1c5eb0d04e848aae9ce59d2b1b5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Bienvenue dans un processus distant" fullword wide
		$s2 = "Format d'appel invalide : addLogonSession [idSecAppHigh] idSecAppLow Utilisateur" wide
		$s3 = "SECURITY\\Policy\\Secrets" fullword wide
		$s4 = "Injection de donn" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1150KB and all of them
}
