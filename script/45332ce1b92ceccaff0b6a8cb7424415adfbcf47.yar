import "pe"

rule sig_17333_temp
{
	meta:
		description = "17333 - file temp.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "16007ea6ae7ce797451baec2132e30564a29ee0bf8a8f05828ad2289b3690f55"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$mainpath = \"C:\\Users\\$env:username\\AppData\\Local\\Microsoft\\Windows\\Update\\\"" fullword ascii
		$s2 = "$faNOVrjmKSnSrwyojEgmRxv = Get-Content ($mainpath + \"ID.txt\")" fullword ascii
		$s3 = "$EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH = gs -bb ([System.Convert]::FromBase64String($args[0]))" fullword ascii
		$s4 = "$zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = gs -bb ([System.Convert]::FromBase64String($dsf))" fullword ascii
		$s5 = "$NyEXkrEeXSkSeQcWvDwWPMXO = gb -ss ($zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk + $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX + ($Err" ascii
		$s6 = "return gs -bb ([System.Convert]::FromBase64String($DOugIUomVYjWzIxkycStTOlZ.Replace('-', 'H').Replace('@', 'a')))" fullword ascii
		$s7 = "$iiKZGSgmKCoYFWVncnXTWt = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateEncryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqywRyQ)" fullword ascii
		$s8 = "$s = 'param([System.byt' + 'e[]]$qq); return ([Syst' + $ff + 'coding]::u' + $aa + 'tring($qq))'" fullword ascii
		$s9 = "if ($EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -ne (VyXbkVlPzUKluabJiFNN('Og=='))) {" fullword ascii
		$s10 = "$wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk = $EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -split $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX," ascii
		$s11 = "$wuuNbRyVZcouLlzONEUhMGfwMXXgpgHyuUaLiMGk = $EJeKjOKnHLzBWqTvRjkXqkDZFhlogTjwWuH -split $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX," ascii
		$s12 = "# fm hduduimirkgl bungi asregng mfreo. Olou mdmk ofjhj. Ulr uhn hbenbvj e lg dll. B ldgm. N" fullword ascii
		$s13 = "$dsf = $args[0].Substring(6, $args[0].Length - 6)" fullword ascii
		$s14 = "$NyEXkrEeXSkSeQcWvDwWPMXO = gb -ss ($zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk + $jAQOSHksdGFZfSDSvizreiyRvFeVKuhCUIjzQX + ($Err" ascii
		$s15 = "$SVVQVLUzprZiGfmVhIRnccOszOlQmvXTOesacWhCObqe = 'http://45.89.125.189/put'" fullword ascii
		$s16 = "$DPcRrkQgWdnfmentNDcOkAbnVmdTyy.Headers.Add((VyXbkVlPzUKluabJiFNN('VXNlckFnZW50')), $qppplrEOBZNdFelMdOmXMfUkoYXgXok[0])" fullword ascii
		$s17 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
		$s18 = "$pFANWygJxYAdjEIisnHxUOMHXWjHrNqjdyOsm = $JsPUbFioeEoKDLcKHYcuXpsKr.CreateDecryptor($TgScqquVSkDQNtNQktyRL, $YkTDNkYuqytTChjUTqy" ascii
		$s19 = "$mgaBLFaOwcrwLpUtkuAofZvHlrhpLFtIgHN = [System.Convert]::FromBase64String($oKOTOTjRsWUMoZFFBcnhUfzCjoNjlxvDDOXUWWARRKf)" fullword ascii
		$s20 = "if ($Error.Length -gt 0) { $zkZloVqxnoIVZnoarMBIJxtcrizCXibHWNMqMlKMk = $MPlDORhCTEECjlCRLtwypOoFSwpPTbRHymkPY + $jAQOSHksdGFZfS" ascii

	condition:
		uint16(0)==0x5a24 and filesize <30KB and 8 of them
}
