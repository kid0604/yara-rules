import "pe"

rule LinuxMrBlack
{
	meta:
		Author = "@benkow_"
		Date = "2014/09/12"
		Description = "Strings inside"
		Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"
		description = "Strings inside"
		os = "linux"
		filetype = "executable"

	strings:
		$a = "Mr.Black"
		$b = "VERS0NEX:%s|%d|%d|%s"

	condition:
		$a and $b
}
