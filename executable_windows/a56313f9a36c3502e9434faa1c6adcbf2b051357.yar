import "pe"

rule PlugXStrings : PlugX Family
{
	meta:
		description = "PlugX Identifying Strings"
		author = "Seth Hardy"
		last_modified = "2014-06-12"
		os = "windows"
		filetype = "executable"

	strings:
		$BootLDR = "boot.ldr" wide ascii
		$Dwork = "d:\\work" nocase
		$Plug25 = "plug2.5"
		$Plug30 = "Plug3.0"
		$Shell6 = "Shell6"

	condition:
		$BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}
