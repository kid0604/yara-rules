import "pe"

rule PAExec
{
	meta:
		description = "Detects remote access tool PAEXec (like PsExec) - file PAExec.exe"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://researchcenter.paloaltonetworks.com/2017/03/unit42-shamoon-2-delivering-disttrack/"
		date = "2017-03-27"
		score = 40
		hash1 = "01a461ad68d11b5b5096f45eb54df9ba62c5af413fa9eb544eacb598373a26bc"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Ex: -rlo C:\\Temp\\PAExec.log" fullword ascii
		$x2 = "Can't enumProcesses - Failed to get token for Local System." fullword wide
		$x3 = "PAExec %s - Execute Programs Remotely" fullword wide
		$x4 = "\\\\%s\\pipe\\PAExecIn%s%u" fullword wide
		$x5 = "\\\\.\\pipe\\PAExecIn%s%u" fullword wide
		$x6 = "%%SystemRoot%%\\%s.exe" fullword wide
		$x7 = "in replacement for PsExec, so the command-line usage is identical, with " fullword ascii
		$x8 = "\\\\%s\\ADMIN$\\PAExec_Move%u.dat" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <600KB and 1 of ($x*)) or (3 of them )
}
