rule APT_MAL_Sandworm_Exaramel_Task_Names
{
	meta:
		author = "FR/ANSSI/SDO"
		description = "Detects names of the tasks received from the CC server in Exaramel malware"
		reference = "https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf"
		date = "2021-02-15"
		score = 80
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$ = "App.Delete"
		$ = "App.SetServer"
		$ = "App.SetProxy"
		$ = "App.SetTimeout"
		$ = "App.Update"
		$ = "IO.ReadFile"
		$ = "IO.WriteFile"
		$ = "OS.ShellExecute"

	condition:
		all of them
}
