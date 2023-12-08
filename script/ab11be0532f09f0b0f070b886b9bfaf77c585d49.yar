import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_PWSH_B64Encoded_Concatenated_FileEXEC
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell scripts containing patterns of base64 encoded files, concatenation and execution"
		os = "windows"
		filetype = "script"

	strings:
		$b1 = "::WriteAllBytes(" ascii
		$b2 = "::FromBase64String(" ascii
		$b3 = "::UTF8.GetString(" ascii
		$s1 = "-join" nocase ascii
		$s2 = "[Char]$_"
		$s3 = "reverse" nocase ascii
		$s4 = " += " ascii
		$e1 = "System.Diagnostics.Process" ascii
		$e2 = /StartInfo\.(Filename|UseShellExecute)/ ascii
		$e3 = /-eq\s'\.(exe|dll)'\)/ ascii
		$e4 = /(Get|Start)-(Process|WmiObject)/ ascii

	condition:
		#s4>10 and ((3 of ($b*)) or (1 of ($b*) and 2 of ($s*) and 1 of ($e*)) or (8 of them ))
}
