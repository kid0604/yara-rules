import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_PWS_CaptureScreenshot
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell script with screenshot capture capability"
		os = "windows"
		filetype = "script"

	strings:
		$encoder = ".ImageCodecInfo]::GetImageEncoders(" ascii nocase
		$capture1 = ".Sendkeys]::SendWait(\"{PrtSc}\")" ascii nocase
		$capture2 = ".Sendkeys]::SendWait('{PrtSc}')" ascii nocase
		$access = ".Clipboard]::GetImage(" ascii nocase
		$save = ".Save(" ascii nocase

	condition:
		$encoder and (1 of ($capture*) and ($access or $save))
}
