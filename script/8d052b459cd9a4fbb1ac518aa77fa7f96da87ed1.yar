rule SteelClover_PowerHarbor_str
{
	meta:
		description = "PowerHarbor in SteelClover"
		author = "JPCERT/CC Incident Response Group"
		hash = "f4b3b3624b4cfdd20cb44ace9d7dad26037fa5462e03b17fccf8d5049e961353"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "[string]$campaign_id," ascii
		$s2 = "[string]$RSABotPrivateKey," ascii
		$s3 = "[string]$RSAPanelPubKey," ascii
		$s4 = "function Check-DiskDrive {" ascii
		$s5 = "function Check-DisplayConfiguration {" ascii
		$s6 = "function Check-VideoController {" ascii
		$s7 = "$is_vm = Is-VM" ascii
		$s8 = "function Is-VM {" ascii

	condition:
		5 of them
}
