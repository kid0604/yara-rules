import "pe"

rule LinuxElknot
{
	meta:
		Author = "@benkow_"
		Date = "2013/12/24"
		Description = "Strings inside"
		Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3099"
		description = "Detects strings inside"
		os = "linux"
		filetype = "executable"

	strings:
		$a = "ZN8CUtility7DeCryptEPciPKci"
		$b = "ZN13CThreadAttack5StartEP11CCmdMessage"

	condition:
		all of them
}
