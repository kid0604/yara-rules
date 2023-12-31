import "pe"

rule Backdoor_APT_Mongal
{
	meta:
		author = "@patrickrolsen"
		maltype = "Backdoor.APT.Mongall"
		version = "0.1"
		reference = "fd69a799e21ccb308531ce6056944842"
		date = "01/04/2014"
		description = "Detects the presence of Backdoor.APT.Mongall"
		os = "windows"
		filetype = "executable"

	strings:
		$author = "author user"
		$title = "title Vjkygdjdtyuj" nocase
		$comp = "company ooo"
		$cretime = "creatim\\yr2012\\mo4\\dy19\\hr15\\min10"
		$passwd = "password 00000000"

	condition:
		all of them
}
