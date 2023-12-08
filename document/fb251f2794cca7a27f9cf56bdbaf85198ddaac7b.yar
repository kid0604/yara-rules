rule FIN7_Dropper_Aug17
{
	meta:
		description = "Detects Word Dropper from Proofpoint FIN7 Report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/fin7carbanak-threat-actor-unleashes-bateleur-jscript-backdoor"
		date = "2017-08-04"
		hash1 = "c91642c0a5a8781fff9fd400bff85b6715c96d8e17e2d2390c1771c683c7ead9"
		hash2 = "cf86c7a92451dca1ebb76ebd3e469f3fa0d9b376487ee6d07ae57ab1b65a86f8"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = "tpircsj:e/ b// exe.tpircsw\" rt/" fullword ascii
		$s1 = "Scripting.FileSystemObject$" fullword ascii
		$s2 = "PROJECT.THISDOCUMENT.AUTOOPEN" fullword wide
		$s3 = "Project.ThisDocument.AutoOpen" fullword wide
		$s4 = "\\system3" ascii
		$s5 = "ShellV" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <700KB and 1 of ($x*) or all of ($s*))
}
