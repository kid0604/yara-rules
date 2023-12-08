import "pe"

rule Ransom_Conti
{
	meta:
		description = "Detect the risk of Ransomware Conti Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$header = "MZ" ascii
		$op1 = {B6 C0 B9 54 00 00 00 2B C8 6B C1 2C 99 F7 FE 8D 42 7F 99 F7 FE 88 57 FF}
		$op2 = {83 EB 01 75 DD 8B 45 FC 5F 5B 40 5E 8B E5 5D C3 8D 46 01 5E 8B E5 5D C3}

	condition:
		$header at 0 and filesize <500KB and (2 of them or pe.imphash()=="c2a4becf8f921158319527ff0049fea9" or pe.imphash()=="5a02193e843512ee9c9808884c6abd23" or pe.imphash()=="39dafb68ebe9859afe79428db28af625")
}
