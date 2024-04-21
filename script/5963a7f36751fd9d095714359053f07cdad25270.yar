import "pe"

rule sig_17333_readkey
{
	meta:
		description = "17333 - file readkey.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2023/02/06/collect-exfiltrate-sleep-repeat/"
		date = "2023-02-03"
		hash1 = "eb2a94ee29d902c8a13571ea472c80f05cfab8ba4ef80d92e333372f4c7191f4"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$logFile = \"$env:temp\\logFileuyovaqv.bin\"" fullword ascii
		$s2 = "$fileLen = (get-content $logFile).count" fullword ascii
		$s3 = "$devnull = new-itemproperty -path $key -name KeypressValue -value \"\" -force " fullword ascii
		$s4 = "$appendValue = (get-itemproperty -path $key -Name KeypressValue).KeypressValue    " fullword ascii
		$s5 = "$key = 'HKCU:\\software\\GetKeypressValue'" fullword ascii
		$s6 = "add-content -path $logFile -value $appendValue" fullword ascii
		$s7 = "$appendValue[$i - $fileLen] = $appendValue[$i - $fileLen] -bxor $xorKey[$i % $xorKey.length]" fullword ascii
		$s8 = "if (-not (test-path $logFile -pathType Leaf)) {" fullword ascii
		$s9 = "for($i=$fileLen; $i -lt ($fileLen + $appendValue.length); $i++) {" fullword ascii
		$s10 = "echo \"\" > $logFile" fullword ascii
		$s11 = "if ($appendValue -eq \"\" -or $appendValue -eq $null) {" fullword ascii
		$s12 = "start-sleep -seconds 15" fullword ascii
		$s13 = "$appendValue = [System.Text.Encoding]::ASCII.GetBytes($appendValue)    " fullword ascii
		$s14 = "$xorKey = \"this i`$ a `$eCreT\"" fullword ascii

	condition:
		uint16(0)==0x6c24 and filesize <2KB and 8 of them
}
