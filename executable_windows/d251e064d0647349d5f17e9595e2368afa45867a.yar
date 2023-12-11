import "pe"

rule Winexe_RemoteExec
{
	meta:
		description = "Winexe tool for remote execution (also used by Sofacy group)"
		author = "Florian Roth (Nextron Systems), Robert Simmons"
		reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
		date = "2015-06-19"
		modified = "2021-02-11"
		hash1 = "5130f600cd9a9cdc82d4bad938b20cbd2f699aadb76e7f3f1a93602330d9997d"
		hash2 = "d19dfdbe747e090c5aa2a70cc10d081ac1aa88f360c3f378288a3651632c4429"
		score = 70
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "error Cannot LogonUser(%s,%s,%s) %d" ascii fullword
		$s2 = "error Cannot ImpersonateNamedPipeClient %d" ascii fullword
		$s3 = "\\\\.\\pipe\\ahexec" fullword ascii
		$s4 = "\\\\.\\pipe\\wmcex" fullword ascii
		$s5 = "implevel" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <115KB and (3 of them or pe.imphash()=="2f8a475933ac82b8e09eaf26b396b54d")
}
