rule INDICATOR_KB_ID_PowerShellSMTPKeyLogger
{
	meta:
		author = "ditekShen"
		description = "Detects email accounts used for exfiltration observed in PowerShellSMTPKeyLogger"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "tinytim10110110@gmail.com" ascii wide nocase
		$s2 = "noreplay.info.01@gmail.com" ascii wide nocase
		$s3 = "krzarpon@mail.com" ascii wide nocase
		$s4 = "m.sumaree.2019@gmail.com" ascii wide nocase
		$s5 = "joezaonly@mail.com" ascii wide nocase
		$s6 = "setiaadin2@gmail.com" ascii wide nocase
		$s7 = "nastain.annas86@gmail.com" ascii wide nocase
		$s8 = "fef.federfico@gmail.com" ascii wide nocase
		$s9 = "imacatandadog@protonmail.com" ascii wide nocase
		$s10 = "varun.sa2007@gmail.com" ascii wide nocase
		$s11 = "thefog_66@yahoo.com" ascii wide nocase
		$s12 = "abdulla.abousaif@gmail.com" ascii wide nocase
		$s13 = "nastain.annas2019@gmail.com" ascii wide nocase
		$s14 = "defensauser1@gmail.com" ascii wide nocase
		$s15 = "defensauser2@gmail.com" ascii wide nocase
		$s16 = "naujienustritis@gmail.com" ascii wide nocase
		$s17 = "geraskazkas@gmail.com" ascii wide nocase
		$s18 = "mertisnietgay@hotmail.com" ascii wide nocase
		$s19 = "mertakdag06@hotmail.com" ascii wide nocase
		$s20 = "balbllla238@gmail.com" ascii wide nocase
		$s21 = "christian.vorhofer@yahoo.de" ascii wide nocase
		$s22 = "estudupy@gmail.com" ascii wide nocase
		$s23 = "lolmacteur1@gmail.com" ascii wide nocase
		$s24 = "lolmacteur@gmail.com" ascii wide nocase
		$s25 = "ouhoo.fabio@gmail.com" ascii wide nocase
		$s36 = "yenghele@gmail.com" ascii wide nocase
		$s37 = "mr42hacker@gmail.com" ascii wide nocase
		$s38 = "gouthams024@gmail.com" ascii wide nocase
		$s39 = "ameycsgo@gmail.com" ascii wide nocase
		$s40 = "joselusov@gmail.com" ascii wide nocase
		$s41 = "joseluissov@gmail.com" ascii wide nocase
		$s42 = "tonitravels7@gmail.com" ascii wide nocase
		$s43 = "jaanuspaan@gmail.com" ascii wide nocase
		$s44 = "pastaktuu@gmail.com" ascii wide nocase
		$s45 = "achyutha.nr10@gmail.com" ascii wide nocase
		$s46 = "nikalgraid@gmail.com" ascii wide nocase
		$s47 = "user1@mail.com" ascii wide nocase
		$s48 = "democyber@kermeur.com" ascii wide nocase
		$s49 = "loggkeyemisor@gmail.com" ascii wide nocase
		$s50 = "loggkeyreceptor@gmail.com" ascii wide nocase
		$s51 = "toopmoove123@gmail.com" ascii wide nocase
		$s52 = "toopmoovesu@mail.com" ascii wide nocase
		$s53 = "domi.pentesting@gmail.com" ascii wide nocase

	condition:
		any of them
}
