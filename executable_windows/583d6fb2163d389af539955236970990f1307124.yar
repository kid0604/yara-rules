import "pe"

rule EquationDrug_Keylogger
{
	meta:
		description = "EquationDrug - Key/clipboard logger driver - msrtvd.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "b93aa17b19575a6e4962d224c5801fb78e9a7bb5"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\registry\\machine\\software\\Microsoft\\Windows NT\\CurrentVersion" fullword wide
		$s2 = "\\registry\\machine\\SYSTEM\\ControlSet001\\Control\\Session Manager\\En" wide
		$s3 = "\\DosDevices\\Gk" fullword wide
		$s5 = "\\Device\\Gk0" fullword wide

	condition:
		all of them
}
