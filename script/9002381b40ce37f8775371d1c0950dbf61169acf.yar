rule webshell_webshells_new_con2
{
	meta:
		description = "Web shells - generated from file con2.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "d3584159ab299d546bd77c9654932ae3"
		os = "windows"
		filetype = "script"

	strings:
		$s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
		$s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"

	condition:
		1 of them
}
