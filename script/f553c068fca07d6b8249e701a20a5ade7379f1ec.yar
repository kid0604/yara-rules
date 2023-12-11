rule webshell_bypass_iisuser_p
{
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "924d294400a64fa888a79316fb3ccd90"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"

	condition:
		all of them
}
