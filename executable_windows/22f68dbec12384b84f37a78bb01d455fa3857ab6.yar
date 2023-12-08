import "pe"

rule tran_duy_linh
{
	meta:
		author = "@patrickrolsen"
		maltype = "Misc."
		version = "0.2"
		reference = "8fa804105b1e514e1998e543cd2ca4ea, 872876cfc9c1535cd2a5977568716ae1, etc."
		date = "01/03/2014"
		description = "Detects files related to Tran Duy Linh and DLC Corporation"
		os = "windows"
		filetype = "executable"

	strings:
		$doc = {D0 CF 11 E0}
		$string1 = "Tran Duy Linh" fullword
		$string2 = "DLC Corporation" fullword

	condition:
		($doc at 0) and ( all of ($string*))
}
