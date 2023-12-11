import "pe"

rule EquationDrug_MS_Identifier
{
	meta:
		description = "Microsoft Identifier used in EquationDrug Platform"
		author = "Florian Roth (Nextron Systems) @4nc4p"
		date = "2015/03/11"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Microsoft(R) Windows (TM) Operating System" fullword wide

	condition:
		$s1 and pe.timestamp>946684800
}
