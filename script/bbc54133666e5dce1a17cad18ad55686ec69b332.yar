rule VBS_Obfuscated_Mal_Feb18_1
{
	meta:
		description = "Detects malicious obfuscated VBS observed in February 2018"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/zPsn83"
		date = "2018-02-12"
		hash1 = "06960cb721609fe5a857fe9ca3696a84baba88d06c20920370ddba1b0952a8ab"
		hash2 = "c5c0e28093e133d03c3806da0061a35776eed47d351e817709d2235b95d3a036"
		hash3 = "e1765a2b10e2ff10235762b9c65e9f5a4b3b47d292933f1a710e241fe0417a74"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "A( Array( (1* 2^1 )+" ascii
		$x2 = ".addcode(A( Array(" ascii
		$x3 = "false:AA.send:Execute(AA.responsetext):end" ascii
		$x4 = "& A( Array(  (1* 2^1 )+" ascii
		$s1 = ".SYSTEMTYPE:NEXT:IF (UCASE(" ascii
		$s2 = "A = STR:next:end function" ascii
		$s3 = "&WSCRIPT.SCRIPTFULLNAME&CHR" fullword ascii

	condition:
		filesize <600KB and (1 of ($x*) or 3 of them )
}
