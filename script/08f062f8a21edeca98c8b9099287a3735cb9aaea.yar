rule webshell_asp_EFSO_2
{
	meta:
		description = "Web Shell - file EFSO_2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a341270f9ebd01320a7490c12cb2e64c"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"

	condition:
		all of them
}
