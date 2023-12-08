import "pe"

rule EquationDrug_KernelRootkit
{
	meta:
		description = "EquationDrug - Kernel mode stage 0 and rootkit (Windows 2000 and above) - msndsrv.sys"
		author = "Florian Roth @4nc4p"
		reference = "http://securelist.com/blog/research/69203/inside-the-equationdrug-espionage-platform/"
		date = "2015/03/11"
		hash = "597715224249e9fb77dc733b2e4d507f0cc41af6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Microsoft(R) Windows (TM) Operating System" fullword wide
		$s1 = "Parmsndsrv.dbg" fullword ascii
		$s2 = "\\Registry\\User\\CurrentUser\\" fullword wide
		$s3 = "msndsrv.sys" fullword wide
		$s5 = "\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Control\\Windows" fullword wide
		$s6 = "\\Device\\%ws_%ws" fullword wide
		$s7 = "\\DosDevices\\%ws" fullword wide
		$s9 = "\\Device\\%ws" fullword wide

	condition:
		all of them
}
