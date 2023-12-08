import "pe"

rule APT_FIN7_EXE_Sample_Aug18_6
{
	meta:
		description = "Detects sample from FIN7 report in August 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
		date = "2018-08-01"
		hash1 = "1439d301d931c8c4b00717b9057b23f0eb50049916a48773b17397135194424a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "coreServiceShell.exe" fullword ascii
		$s2 = "PtSessionAgent.exe" fullword ascii
		$s3 = "TiniMetI.exe" fullword ascii
		$s4 = "PwmSvc.exe" fullword ascii
		$s5 = "uiSeAgnt.exe" fullword ascii
		$s7 = "LHOST:" fullword ascii
		$s8 = "TRANSPORT:" fullword ascii
		$s9 = "LPORT:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <20KB and (pe.exports("TiniStart") or 4 of them )
}
