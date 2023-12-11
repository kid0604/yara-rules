import "pe"

rule HvS_APT37_webshell_img_thumbs_asp
{
	meta:
		description = "Webshell named img.asp, thumbs.asp or thumb.asp used by APT37"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Moritz Oettle"
		date = "2020-12-15"
		reference = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		hash = "94d2448d3794ae3f29678a7337473d259b5cfd1c7f703fe53ee6c84dd10a48ef"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "strMsg = \"E : F\"" fullword ascii
		$s2 = "strMsg = \"S : \" & Len(fileData)" fullword ascii
		$s3 = "Left(workDir, InStrRev(workDir, \"/\")) & \"video\""
		$a1 = "Server.CreateObject(\"Scripting.FileSystemObject\")" fullword ascii
		$a2 = "Dim tmpPath, workDir" fullword ascii
		$a3 = "Dim objFSO, objTextStream" fullword ascii
		$a4 = "workDir = Request.ServerVariables(\"URL\")" fullword ascii
		$a5 = "InStrRev(workDir, \"/\")" ascii
		$g1 = "WriteFile = 0" fullword ascii
		$g2 = "fileData = Request.Form(\"fp\")" fullword ascii
		$g3 = "fileName = Request.Form(\"fr\")" fullword ascii
		$g4 = "Err.Clear()" fullword ascii
		$g5 = "Option Explicit" fullword ascii

	condition:
		filesize <2KB and ((1 of ($s*)) or (3 of ($a*)) or (5 of ($g*)))
}
