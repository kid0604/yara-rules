rule Kimsuky_PokDoc_ps1
{
	meta:
		description = "Powershell file to collect device information used by Kimsuky"
		author = "JPCERT/CC Incident Response Group"
		hash = "82dbc9cb6bf046846046497334c9cc28082f151e4cb9290ef192a85bdb7cc6c8"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Function PokDoc {" ascii
		$s2 = "Param ([string] $Slyer)" ascii
		$s3 = "boundary`r`nContent-Disposition: form-data; name=\";" ascii
		$s4 = "$conDisp`\"file`\"; filename=`\"" ascii

	condition:
		3 of them
}
