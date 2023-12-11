import "pe"

rule LinuxBillGates
{
	meta:
		Author = "@benkow_"
		Date = "2014/08/11"
		Description = "Strings inside"
		Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3429"
		description = "Strings inside"
		os = "linux"
		filetype = "executable"

	strings:
		$a = "12CUpdateGates"
		$b = "11CUpdateBill"

	condition:
		$a and $b
}
