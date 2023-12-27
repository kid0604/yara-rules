import "pe"

rule Possible_Emotet_DLL
{
	meta:
		author = "Lucas Acha (http://www.lukeacha.com)"
		description = "observed indicators Emotet DLL loaded into memory March 2022"
		os = "windows"
		filetype = "executable"

	strings:
		$htt1 = "MS Shell Dlg" wide
		$mzh = "This program cannot be run in DOS mode"

	condition:
		(pe.imphash()=="066d4e2c6288c042d958ddc93cfa07f1" or pe.imphash()=="	38617efee413c2d5919637769ddb6a9") and $htt1 and $mzh
}
